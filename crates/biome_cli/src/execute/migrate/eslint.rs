use biome_console::{markup, Console, ConsoleExt};
use biome_deserialize::json::deserialize_from_json_str;
use biome_deserialize::Merge;
use biome_deserialize::{
    Deserializable, DeserializableValue, DeserializationDiagnostic, DeserializationVisitor,
    VisitableType,
};
use biome_deserialize_macros::Deserializable;
use biome_diagnostics::{DiagnosticExt, PrintDiagnostic};
use biome_fs::{FileSystem, OpenOptions};
use biome_json_parser::JsonParserOptions;
use biome_rowan::TextRange;
use biome_service::configuration::linter::RulePlainConfiguration;
use biome_service::DynRef;
use rustc_hash::FxHashMap;
use rustc_hash::FxHashSet;
use std::borrow::Cow;
use std::collections::hash_set;
use std::hash::{Hash, Hasher};
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::vec;
use std::{any::TypeId, marker::PhantomData, ops::Deref};

use crate::diagnostics::MigrationDiagnostic;
use crate::CliDiagnostic;

use super::{eslint_jsxa11y, eslint_typescript, eslint_unicorn};

/// This modules includes implementations for deserializing an eslint configuration.
///
/// The defined types follow the ESlint configuration schema described at
/// <https://github.com/eslint/eslint/blob/ce838adc3b673e52a151f36da0eedf5876977514/lib/shared/types.js>.
///
/// See [super::eslint_to_biome] for converting an ESlint config to a Biome config.
///
/// Each ESlint plugin has its own module in which rule options and plugin presets are defined.
/// For example, the ESlint TypeScript plugin is defined in [super::eslint_typescript].
/// Note that we don't need to deserialise every existing rule option.
/// We only need to deserialise options that have equivalent biome options.
/// This greatly reduces the amount of work involved.

/// List of ESlint **legacy** configuration files.
///
/// See https://eslint.org/docs/latest/use/configure/configuration-files
///
/// Order is important.
/// It translates the priority of the files.
/// For example, ESlint looks for `./.eslintrc.js` before looking for `./.eslintrc.json`.
const LEGACY_CONFIG_FILES: [&str; 5] = [
    // Prefixed with `./` to ensure that it is loadable via `import()`
    "./.eslintrc.js",
    // Prefixed with `./` to ensure that it is loadable via `import()`
    "./.eslintrc.cjs",
    ".eslintrc.yaml",
    ".eslintrc.yml",
    ".eslintrc.json",
];

/// ESlint flat configuration files.
///
/// See https://eslint.org/docs/latest/use/configure/configuration-files-new
const FLAT_CONFIG_FILES: [&str; 3] = [
    "./eslint.config.js",
    "./eslint.config.mjs",
    "./eslint.config.cjs",
];

/// Returns the ESlint configuration file in the working directory with the highest priority.
///
/// This function respects the priority between ESlint configuration files.
/// For example, it looks for `./.eslintrc.js` before looking for `./.eslintrc.json`.
///
/// Unlike ESlint, it doesn't look for a configuration file in parent directories
/// when no configuration file is found in the working directory.
/// It also doesn't extract an embedded ESlint configuration in `package.json`.
///
/// Deserialization errors are reported using `console`.
/// Other errors (File Not found, unspported config format, ...) are directly returned.
///
/// We extract the ESlint configuration from a JavaScript file, by invocating `node`.
///
/// The `extends` field is recusively resolved.
pub(crate) fn read_eslint_config(
    fs: &DynRef<'_, dyn FileSystem>,
    console: &mut dyn Console,
) -> Result<ConfigData, CliDiagnostic> {
    for config_path_str in LEGACY_CONFIG_FILES {
        let path = Path::new(config_path_str);
        if fs.path_exists(path) {
            return load_config(fs, path, console);
        }
    }
    for config_path_str in FLAT_CONFIG_FILES {
        let path = Path::new(config_path_str);
        if fs.path_exists(path) {
            return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                reason: "ESlint flat configuration format is not supported yet.".to_string(),
            }));
        }
    }
    Err(CliDiagnostic::MigrateError(MigrationDiagnostic { reason: "The default ESlint configuration file `.eslintrc.*` was not found in the working directory.".to_string()}))
}

fn load_config(
    fs: &DynRef<'_, dyn FileSystem>,
    path: &Path,
    console: &mut dyn Console,
) -> Result<ConfigData, CliDiagnostic> {
    let (deserialized, diagnostics) = match path.extension().and_then(|file_ext| file_ext.to_str()) {
        Some("json") => {
            let mut file = fs.open_with_options(path, OpenOptions::default().read(true))?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            deserialize_from_json_str::<ConfigData>(
                &content,
                JsonParserOptions::default()
                    .with_allow_trailing_commas()
                    .with_allow_comments(),
                "",
            )
        },
        Some("js" | "cjs") => {
            let NodeResolveResult { content, ..} = load_config_with_node(&path.to_string_lossy())?;
            deserialize_from_json_str::<ConfigData>(
                &content,
                JsonParserOptions::default(),
                "",
            )
        },
        Some(ext) => return Err(CliDiagnostic::MigrateError(MigrationDiagnostic{ reason: format!("ESlint configuration ending with the extension `{ext}` are not supported.") })),
        None => return Err(CliDiagnostic::MigrateError(MigrationDiagnostic{ reason: "The ESlint configuration format cannot be determined because the file has no extension.".to_string() })),
    }.consume();
    let path_str = path.to_string_lossy();
    for diagnostic in diagnostics.into_iter().filter(|diag| {
        matches!(
            diag.severity(),
            biome_diagnostics::Severity::Fatal
                | biome_diagnostics::Severity::Error
                | biome_diagnostics::Severity::Warning
        )
    }) {
        let diagnostic = diagnostic.with_file_path(path_str.to_string());
        console.error(markup! {{PrintDiagnostic::simple(&diagnostic)}});
    }
    if let Some(mut result) = deserialized {
        // recursively resolve the `extends` field.
        while !result.extends.is_empty() {
            resolve_extends(&mut result, console);
        }
        Ok(result)
    } else {
        Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
            reason: "Could not deserialize the Eslint configuration file".to_string(),
        }))
    }
}

#[derive(Debug)]
struct NodeResolveResult {
    /// Resolved path of the file
    resolved_path: String,
    /// File content
    content: String,
}

/// Imports `specifier` using Node's `import()` or node's `require()` and
/// returns the JSONified content of its default export.
fn load_config_with_node(specifier: &str) -> Result<NodeResolveResult, CliDiagnostic> {
    let content_output = Command::new("node")
        .arg("--eval")
        .arg(format!(
            "import('{specifier}').then((c) => console.log(JSON.stringify(c.default)))"
        ))
        .output();
    match content_output {
        Err(_) => {
            Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                reason: "The `node` program doesn't exist or cannot be invoked by Biome.\n`node` is invoked to resolve ESlint configurations written in JavaScript.\nThis includes shared configurations and plugin configurations imported with ESlint's `extends`.".to_string()
            }))
        },
        Ok(output) => {
            let path_output = Command::new("node")
                .arg("--print")
                .arg(format!(
                    "require.resolve('{specifier}')"
                ))
                .output();
            let resolved_path = path_output.ok().map_or(String::new(), |path_output| String::from_utf8_lossy(&path_output.stdout).trim().to_string());
            if !output.stderr.is_empty() {
                // Try with `require` before giving up.
                let output2 = Command::new("node")
                    .arg("--print")
                    .arg(format!(
                        "JSON.stringify(require('{specifier}'))"
                    ))
                    .output();
                if let Ok(output2) = output2 {
                    if output2.stderr.is_empty() {
                        return Ok(NodeResolveResult {
                            content: String::from_utf8_lossy(&output2.stdout).to_string(),
                            resolved_path,
                        });
                    }
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                    reason: format!("`node` was invoked to resolve an ESlint configuration. This invocation failed with the following error:\n{stderr}")
                }));
            }
            Ok(NodeResolveResult {
                content: String::from_utf8_lossy(&output.stdout).to_string(),
                resolved_path,
            })
        }
    }
}

/// Returns the configuration from a preset or a nerror if the resolution failed.
///
/// This handles:
/// - native ESlint presets such as `eslint:recommended`;
/// - plugin presets such as `plugin:@typescript-eslint/recommended`;
/// - and shared configurations such as `standard`.
fn load_eslint_extends_config(name: &str) -> Result<ConfigData, CliDiagnostic> {
    let (specifier, resolved_path, deserialized) = if let Some((protocol, rest)) =
        name.split_once(':')
    {
        let (module_name, config_name) = match protocol {
            // e.g. `eslint:recommended`
            //      - module_name: `@eslint/js`
            //      - config_name: `recommended`
            "eslint" => (Cow::Borrowed("@eslint/js"), rest),
            // e.g. `plugin:@typescript-eslint/recommended`
            //      - module_name: `@typescript-eslint/eslint-plugin`
            //      - config_name: `recommended`
            // e.g. `plugin:unicorn/recommended`
            //      - module_name: `eslint-plugin-unicorn`
            //      - config_name: `recommended`
            "plugin" => {
                let Some(config_name) = rest.split('/').last() else {
                    return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                        reason: format!(
                            "The configuration {rest} cannot be resolved. Make sure that your ESlint configuration file is valid."
                        ),
                    }));
                };
                let rest = rest.trim_end_matches(config_name);
                let module_name = rest.trim_end_matches('/');
                let module_name = EslintPackage::Plugin.resolve_name(module_name);
                (module_name, config_name)
            }
            name => {
                return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                    reason: format!(
                        "The module {name} cannot be resolved. This is likely an internal error."
                    ),
                }));
            }
        };
        // load ESlint preset
        let Ok(NodeResolveResult {
            content,
            resolved_path,
        }) = load_config_with_node(&module_name)
        else {
            return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                reason: format!(
                    "The module '{rest}' cannot be loaded. Make sure that the module exists."
                ),
            }));
        };
        let deserialized =
            deserialize_from_json_str::<PluginExport>(&content, JsonParserOptions::default(), "")
                .into_deserialized();
        if let Some(mut deserialized) = deserialized {
            let deserialized = deserialized.configs.remove(config_name);
            if deserialized.is_none() {
                return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                    reason: format!("The ESlint configuration '{config_name}' cannot be extracted from the module '{module_name}'. Make sure that '{config_name}' is a valid configuration name.")
                }));
            }
            (module_name, resolved_path, deserialized)
        } else {
            (module_name, resolved_path, None)
        }
    } else {
        // load ESlint shared config
        let module_name = if matches!(name.as_bytes().first(), Some(b'.' | b'/' | b'#')) {
            // local path
            Cow::Borrowed(name)
        } else {
            EslintPackage::Config.resolve_name(name)
        };
        let Ok(NodeResolveResult {
            content,
            resolved_path,
        }) = load_config_with_node(&module_name)
        else {
            return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                reason: format!(
                    "The module '{module_name}' cannot be loaded. Make sure that the module exists."
                ),
            }));
        };
        let deserialized =
            deserialize_from_json_str::<ConfigData>(&content, JsonParserOptions::default(), "")
                .into_deserialized();
        (module_name, resolved_path, deserialized)
    };
    let Some(mut deserialized) = deserialized else {
        return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
            reason: format!("The ESlint configuration of the module '{specifier}' cannot be extracted. This is likely an internal error.")
        }));
    };
    // Resolve relative path in `extends`.
    deserialized.extends.iter_mut().for_each(|extends_item| {
        if extends_item.starts_with('.') {
            let Some(resolved_path) = Path::new(&resolved_path).parent() else {
                return;
            };
            let mut path = PathBuf::new();
            path.push(resolved_path);
            path.push(Path::new(&extends_item));
            *extends_item = path.to_string_lossy().to_string();
        }
    });
    Ok(deserialized)
}

/// Load and merge included configuration via `self.extends`.
///
/// Unknown presets are ignored.
/// `self.extends` is replaced by an empty array.
fn resolve_extends(config: &mut ConfigData, console: &mut dyn Console) {
    let extensions: Vec<_> = config
        .extends
        .0
        .iter()
        .filter_map(|preset| match load_eslint_extends_config(preset) {
            Ok(config) => Some(config),
            Err(diag) => {
                console.error(markup! {{PrintDiagnostic::simple(&diag)}});
                None
            }
        })
        .collect();
    config.extends.0.clear();
    for ext in extensions {
        config.merge_with(ext);
    }
}

/// ESlint to specific rules to resolve a module name.
/// See https://eslint.org/docs/latest/extend/shareable-configs#using-a-shareable-config
/// See also https://eslint.org/docs/latest/extend/plugins
#[derive(Debug)]
enum EslintPackage {
    Config,
    Plugin,
}
impl EslintPackage {
    fn resolve_name<'a>(&self, name: &'a str) -> Cow<'a, str> {
        let artifact = match self {
            EslintPackage::Config => "eslint-config-",
            EslintPackage::Plugin => "eslint-plugin-",
        };
        debug_assert!(matches!(artifact, "eslint-plugin-" | "eslint-config-"));
        if name.starts_with('@') {
            // handle scoped module
            if let Some((scope, scoped)) = name.split_once('/') {
                if scoped.starts_with(artifact) {
                    Cow::Borrowed(name)
                } else {
                    Cow::Owned(format!("{scope}/{artifact}{scoped}"))
                }
            } else {
                let artifact = artifact.trim_end_matches('-');
                Cow::Owned(format!("{name}/{artifact}"))
            }
        } else if name.starts_with(artifact) {
            Cow::Borrowed(name)
        } else {
            Cow::Owned(format!("{artifact}{name}"))
        }
    }
}

#[derive(Debug, Default, Deserializable)]
#[deserializable(unknown_fields = "allow")]
pub(crate) struct ConfigData {
    pub(crate) extends: Shorthand<String>,
    pub(crate) globals: FxHashMap<String, GlobalConf>,
    /// The glob patterns that ignore to lint.
    pub(crate) ignore_patterns: Shorthand<String>,
    /// The parser options.
    pub(crate) rules: Rules,
    pub(crate) overrides: Vec<OverrideConfigData>,
}
impl Merge for ConfigData {
    fn merge_with(&mut self, mut other: Self) {
        self.extends.merge_with(other.extends);
        self.globals.extend(other.globals);
        self.ignore_patterns.merge_with(other.ignore_patterns);
        self.rules.merge_with(other.rules);
        self.overrides.append(&mut other.overrides);
    }
}

//? ESlint plugins export metadata in their main export.
/// This includes presets in the `configs` field.
#[derive(Debug, Default, Deserializable)]
#[deserializable(unknown_fields = "allow")]
pub(crate) struct PluginExport {
    pub(crate) configs: FxHashMap<String, ConfigData>,
}

#[derive(Debug)]
pub(crate) enum GlobalConf {
    Flag(bool),
    Qualifier(GlobalConfQualifier),
}
impl GlobalConf {
    pub(crate) fn is_enabled(&self) -> bool {
        match self {
            GlobalConf::Flag(result) => *result,
            GlobalConf::Qualifier(qualifier) => !matches!(qualifier, GlobalConfQualifier::Off),
        }
    }
}
impl Deserializable for GlobalConf {
    fn deserialize(
        value: &impl biome_deserialize::DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
    ) -> Option<Self> {
        if value.is_type(VisitableType::STR) {
            Deserializable::deserialize(value, name, diagnostics).map(Self::Qualifier)
        } else {
            Deserializable::deserialize(value, name, diagnostics).map(Self::Flag)
        }
    }
}

#[derive(Debug, Deserializable)]
pub(crate) enum GlobalConfQualifier {
    Off,
    Readable,
    Readonly,
    Writable,
    Writeable,
}

#[derive(Debug, Default, Deserializable)]
#[deserializable(unknown_fields = "allow")]
pub(crate) struct OverrideConfigData {
    pub(crate) extends: Shorthand<String>,
    pub(crate) globals: FxHashMap<String, GlobalConf>,
    /// The glob patterns for excluded files.
    pub(crate) excluded_files: Shorthand<String>,
    /// The glob patterns for target files.
    pub(crate) files: Shorthand<String>,
    pub(crate) rules: Rules,
}

#[derive(Debug, Default)]
pub(crate) struct Shorthand<T>(Vec<T>);
impl<T> Merge for Shorthand<T> {
    fn merge_with(&mut self, mut other: Self) {
        self.0.append(&mut other.0);
    }
}
impl<T> From<T> for Shorthand<T> {
    fn from(value: T) -> Self {
        Self(vec![value])
    }
}
impl<T> Deref for Shorthand<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> DerefMut for Shorthand<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<T> IntoIterator for Shorthand<T> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
impl<T: Deserializable> Deserializable for Shorthand<T> {
    fn deserialize(
        value: &impl DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<DeserializationDiagnostic>,
    ) -> Option<Self> {
        Some(Shorthand(if value.is_type(VisitableType::ARRAY) {
            Deserializable::deserialize(value, name, diagnostics)?
        } else {
            Vec::from_iter([Deserializable::deserialize(value, name, diagnostics)?])
        }))
    }
}

/// Model the possible shapes of an ESlint's rule configuration
#[derive(Debug, Clone)]
pub(crate) enum RuleConf<T = (), U = ()> {
    // `{ rule: <severity> }` and `{ rule: [<severity>] }`
    Severity(Severity),
    // `{ rule: <severity> }` and `{ rule: [<severity>, <option1>] }`
    Option(Severity, T),
    // `{ rule: <severity> }` and `{ rule: [<severity>, <option1>, <option2>] }`
    Options(Severity, T, U),
    // `{ rule: <severity> }` and `{ rule: [<severity>, <option1.1>, <option1.2>, ...] }`
    Spread(Severity, Vec<T>),
}
impl<T, U> RuleConf<T, U> {
    pub(crate) fn severity(&self) -> Severity {
        match self {
            Self::Severity(severity) => *severity,
            Self::Option(severity, _) => *severity,
            Self::Options(severity, _, _) => *severity,
            Self::Spread(severity, _) => *severity,
        }
    }
}
impl<T> RuleConf<T, ()> {
    pub(crate) fn into_vec(self) -> Vec<T> {
        match self {
            RuleConf::Severity(_) => vec![],
            RuleConf::Option(_, value) | RuleConf::Options(_, value, _) => vec![value],
            RuleConf::Spread(_, result) => result,
        }
    }
}
impl<T: Default, U: Default> RuleConf<T, U> {
    pub(crate) fn option_or_default(self) -> T {
        match self {
            RuleConf::Severity(_) | RuleConf::Options(_, _, _) | RuleConf::Spread(_, _) => {
                T::default()
            }
            RuleConf::Option(_, option) => option,
        }
    }
}
impl<T: Deserializable + 'static, U: Deserializable + 'static> Deserializable for RuleConf<T, U> {
    fn deserialize(
        value: &impl biome_deserialize::DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
    ) -> Option<Self> {
        struct Visitor<T, U>(PhantomData<(T, U)>);
        impl<T: Deserializable + 'static, U: Deserializable + 'static> DeserializationVisitor
            for Visitor<T, U>
        {
            type Output = RuleConf<T, U>;
            const EXPECTED_TYPE: VisitableType = VisitableType::ARRAY;
            fn visit_array(
                self,
                values: impl Iterator<Item = Option<impl DeserializableValue>>,
                range: TextRange,
                _name: &str,
                diagnostics: &mut Vec<DeserializationDiagnostic>,
            ) -> Option<Self::Output> {
                let mut values = values.flatten();
                let Some(first_value) = values.next() else {
                    diagnostics.push(
                        DeserializationDiagnostic::new("A severity is expected.").with_range(range),
                    );
                    return None;
                };
                let severity = Deserializable::deserialize(&first_value, "", diagnostics)?;
                if TypeId::of::<T>() == TypeId::of::<()>() {
                    return Some(RuleConf::Severity(severity));
                }
                let Some(second_value) = values.next() else {
                    return Some(RuleConf::Severity(severity));
                };
                let Some(option) = T::deserialize(&second_value, "", diagnostics) else {
                    // Recover by ignoring the failed deserialization
                    return Some(RuleConf::Severity(severity));
                };
                let Some(third_value) = values.next() else {
                    return Some(RuleConf::Option(severity, option));
                };
                if TypeId::of::<U>() != TypeId::of::<()>() {
                    if let Some(option2) = U::deserialize(&third_value, "", diagnostics) {
                        return Some(RuleConf::Options(severity, option, option2));
                    } else {
                        // Recover by ignoring the failed deserialization
                        return Some(RuleConf::Option(severity, option));
                    }
                }
                let Some(option2) = T::deserialize(&third_value, "", diagnostics) else {
                    // Recover by ignoring the failed deserialization
                    return Some(RuleConf::Option(severity, option));
                };
                let mut spread = Vec::new();
                spread.push(option);
                spread.push(option2);
                spread.extend(values.filter_map(|val| T::deserialize(&val, "", diagnostics)));
                Some(RuleConf::Spread(severity, spread))
            }
        }
        if value.is_type(VisitableType::NUMBER) || value.is_type(VisitableType::STR) {
            Deserializable::deserialize(value, name, diagnostics).map(RuleConf::Severity)
        } else {
            value.deserialize(Visitor(PhantomData), name, diagnostics)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserializable)]
#[deserializable(try_from = "NumberOrString")]
pub(crate) enum Severity {
    Off,
    Warn,
    Error,
}
impl TryFrom<NumberOrString> for Severity {
    type Error = &'static str;

    fn try_from(value: NumberOrString) -> Result<Self, &'static str> {
        match value {
            NumberOrString::Number(n) => match n {
                0 => Ok(Severity::Off),
                1 => Ok(Severity::Warn),
                2 => Ok(Severity::Error),
                _ => Err("Severity should be 0, 1 or 2."),
            },
            NumberOrString::String(s) => match s.as_ref() {
                "off" => Ok(Severity::Off),
                "warn" => Ok(Severity::Warn),
                "error" => Ok(Severity::Error),
                _ => Err("Severity should be 'off', 'warn' or 'error'."),
            },
        }
    }
}
impl From<Severity> for RulePlainConfiguration {
    fn from(value: Severity) -> RulePlainConfiguration {
        match value {
            Severity::Off => RulePlainConfiguration::Off,
            Severity::Warn => RulePlainConfiguration::Warn,
            Severity::Error => RulePlainConfiguration::Error,
        }
    }
}
#[derive(Debug, Clone)]
enum NumberOrString {
    Number(u64),
    String(String),
}
impl Deserializable for NumberOrString {
    fn deserialize(
        value: &impl biome_deserialize::DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
    ) -> Option<Self> {
        Some(if value.is_type(VisitableType::STR) {
            Self::String(Deserializable::deserialize(value, name, diagnostics)?)
        } else {
            Self::Number(Deserializable::deserialize(value, name, diagnostics)?)
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct Rules(pub(crate) FxHashSet<Rule>);
impl Merge for Rules {
    fn merge_with(&mut self, other: Self) {
        self.0.extend(other.0);
    }
}
impl IntoIterator for Rules {
    type Item = Rule;
    type IntoIter = hash_set::IntoIter<Rule>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
impl Deref for Rules {
    type Target = FxHashSet<Rule>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Deserializable for Rules {
    fn deserialize(
        value: &impl biome_deserialize::DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
    ) -> Option<Self> {
        struct Visitor;
        impl DeserializationVisitor for Visitor {
            type Output = Rules;
            const EXPECTED_TYPE: VisitableType = VisitableType::MAP;
            fn visit_map(
                self,
                members: impl Iterator<
                    Item = Option<(
                        impl biome_deserialize::DeserializableValue,
                        impl biome_deserialize::DeserializableValue,
                    )>,
                >,
                _range: biome_rowan::TextRange,
                name: &str,
                diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
            ) -> Option<Self::Output> {
                use biome_deserialize::Text;
                let mut result = FxHashSet::default();
                for (key, value) in members.flatten() {
                    let Some(rule_name) = Text::deserialize(&key, "", diagnostics) else {
                        continue;
                    };
                    match rule_name.text() {
                        // Eslint rules with options that we handle
                        "no-restricted-globals" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.insert(Rule::NoRestrictedGlobals(conf));
                            }
                        }
                        // Eslint plugin rules with options that we handle
                        "jsx-a11y/aria-role" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.insert(Rule::Jsxa11yArioaRoles(conf));
                            }
                        }
                        "@typescript-eslint/array-type" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.insert(Rule::TypeScriptArrayType(conf));
                            }
                        }
                        "@typescript-eslint/naming-convention" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.insert(Rule::TypeScriptNamingConvention(conf));
                            }
                        }
                        "unicorn/filename-case" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.insert(Rule::UnicornFilenameCase(conf));
                            }
                        }
                        // Other rules
                        rule_name => {
                            if let Some(conf) =
                                RuleConf::<()>::deserialize(&value, name, diagnostics)
                            {
                                result.insert(Rule::Any(
                                    Cow::Owned(rule_name.to_string()),
                                    conf.severity(),
                                ));
                            }
                        }
                    }
                }
                Some(Rules(result))
            }
        }
        value.deserialize(Visitor, name, diagnostics)
    }
}

#[derive(Debug)]
pub(crate) enum NoRestrictedGlobal {
    Plain(String),
    WithMessage(GlobalWithMessage),
}
impl NoRestrictedGlobal {
    pub(crate) fn into_name(self) -> String {
        match self {
            NoRestrictedGlobal::Plain(name) => name,
            NoRestrictedGlobal::WithMessage(named) => named.name,
        }
    }
}
impl Deserializable for NoRestrictedGlobal {
    fn deserialize(
        value: &impl DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<DeserializationDiagnostic>,
    ) -> Option<Self> {
        if value.is_type(VisitableType::STR) {
            Deserializable::deserialize(value, name, diagnostics).map(NoRestrictedGlobal::Plain)
        } else {
            Deserializable::deserialize(value, name, diagnostics)
                .map(NoRestrictedGlobal::WithMessage)
        }
    }
}
#[derive(Debug, Default, Deserializable)]
pub(crate) struct GlobalWithMessage {
    name: String,
    message: String,
}

#[derive(Debug)]
pub(crate) enum Rule {
    /// Any rule without its options.
    Any(Cow<'static, str>, Severity),
    // Eslint rules with its options
    // We use this to configure equivalent Bione's rules.
    NoRestrictedGlobals(RuleConf<Box<NoRestrictedGlobal>>),
    // Eslint plugins
    Jsxa11yArioaRoles(RuleConf<Box<eslint_jsxa11y::AriaRoleOptions>>),
    TypeScriptArrayType(RuleConf<eslint_typescript::ArrayTypeOptions>),
    TypeScriptNamingConvention(RuleConf<Box<eslint_typescript::NamingConventionSelection>>),
    UnicornFilenameCase(RuleConf<eslint_unicorn::FilenameCaseOptions>),
    // If ypu add new variants, dont forget to update [Rules::deserialize].
}
impl Rule {
    pub(crate) fn name(&self) -> Cow<'static, str> {
        match self {
            Rule::Any(name, _) => name.clone(),
            Rule::NoRestrictedGlobals(_) => Cow::Borrowed("no-restricted-globals"),
            Rule::Jsxa11yArioaRoles(_) => Cow::Borrowed("jsx-a11y/aria-role"),
            Rule::TypeScriptArrayType(_) => Cow::Borrowed("@typescript-eslint/array-type"),
            Rule::TypeScriptNamingConvention(_) => {
                Cow::Borrowed("@typescript-eslint/naming-convention")
            }
            Rule::UnicornFilenameCase(_) => Cow::Borrowed("unicorn/filename-case"),
        }
    }
}
impl Eq for Rule {}
impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}
impl Hash for Rule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}
