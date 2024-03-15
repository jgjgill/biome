use crate::run_cli;
use crate::snap_test::{assert_cli_snapshot, SnapshotPayload};
use biome_console::BufferConsole;
use biome_fs::MemoryFileSystem;
use biome_service::DynRef;
use bpaf::Args;
use std::path::Path;

#[test]
fn migrate_eslintrcjson() {
    let biomejson = r#"{ "linter": { "enabled": true } }"#;
    let eslintrc = r#"{
        "ignore_patterns": [
            "**/*.test.js", // trailing comma amd comment
        ],
        "globals": {
            "var1": "writable",
            "var2": "readonly"
        },
        "rules": {
            "dot-notation": 0,
            "default-param-last": "off",
            "eqeqeq": "warn",
            "getter-return": [2,
                // support unknown options
                { "allowImplicit": true }
            ],
            "no-eval": 1,
            "no-extra-label": ["error"]
        },
        "overrides": [{
            "files": ["bin/*.js", "lib/*.js"],
            "excludedFiles": "*.test.js",
            "rules": {
                "eqeqeq": ["off"]
            }
        }],
        "unknownField": "ignored"
    }"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint"].as_slice()),
    );

    assert!(result.is_ok(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcjson_write() {
    let biomejson = r#"{ "linter": { "enabled": true } }"#;
    let eslintrc = r#"{
        "ignore_patterns": [
            "**/*.test.js", // trailing comma amd comment
        ],
        "globals": {
            "var1": "writable",
            "var2": "readonly"
        },
        "rules": {
            "dot-notation": 0,
            "default-param-last": "off",
            "eqeqeq": "warn",
            "getter-return": [2,
                // support unknown options
                { "allowImplicit": true }
            ],
            "no-eval": 1,
            "no-extra-label": ["error"]
        },
        "overrides": [{
            "files": ["bin/*.js", "lib/*.js"],
            "excludedFiles": "*.test.js",
            "rules": {
                "eqeqeq": ["off"]
            }
        }],
        "unknownField": "ignored"
    }"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint", "--write"].as_slice()),
    );

    assert!(result.is_ok(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson_write",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcjson_donot_override_existing_config() {
    let biomejson = r#"{ "linter": { "rules": { "suspicious": { "noDoubleEquals": "error" } } } }"#;
    let eslintrc = r#"{ "rules": { "eqeqeq": "off" } }"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint"].as_slice()),
    );

    assert!(result.is_ok(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson_donot_override_existing_config",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcjson_exclude_inspired() {
    let biomejson = r#"{}"#;
    let eslintrc = r#"{ "rules": { "no-else-return": "error" } }"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint"].as_slice()),
    );

    assert!(result.is_ok(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson_exclude_inspired",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcjson_include_inspired() {
    let biomejson = r#"{}"#;
    let eslintrc = r#"{ "rules": { "no-else-return": "error" } }"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint", "--include-inspired"].as_slice()),
    );

    assert!(result.is_ok(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson_include_inspired",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcjson_rule_options() {
    let biomejson = r#"{ "linter": { "enabled": true } }"#;
    let eslintrc = r#"{
        "rules": {
            "no-restricted-globals": ["error", "event", "fdescribe"],
            "jsx-a11y/aria-role": ["error", {
                "allowedInvalidRoles": ["text"],
                "ignoreNonDOM": true
            }],
            "@typescript-eslint/array-type": ["error", { "default": "generic" }],
            "@typescript-eslint/naming-convention": ["error",
                {
                    "selector": "enumMember",
                    "format": ["UPPER_CASE"]
                }
            ],
            "unicorn/filename-case": ["error", {
                "cases": {
                    "camelCase": true,
                    "pascalCase": true
                }
            }]
        },
        "overrides": [{
            "files": ["default.js"],
            "rules": {
                "no-restricted-globals": "error",
                "jsx-a11y/aria-role": "error",
                "@typescript-eslint/array-type": "error",
                "@typescript-eslint/naming-convention": "error",
                "unicorn/filename-case": "error"
            }
        }, {
            "files": ["alternative.js"],
            "rules": {
                "no-restricted-globals": ["error",
                    {
                        "name": "event",
                        "message": "Use local parameter instead."
                    },
                    {
                        "name": "fdescribe",
                        "message": "Do not commit fdescribe. Use describe instead."
                    }
                ],
                "@typescript-eslint/array-type": ["error", { "default": "array" }],
                "@typescript-eslint/naming-convention": ["error",
                    {
                        "selector": "default",
                        "format": ["UPPER_CASE"]
                    }
                ],
                "unicorn/filename-case": ["error", {
                    "case": "kebabCase",
                    "multipleFileExtensions": true
                }]
            }
        }],
    }"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint", "--include-inspired"].as_slice()),
    );

    assert!(result.is_ok(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson_rule_options",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcjson_presets() {
    let biomejson = r#"{ "linter": { "enabled": true } }"#;
    let eslintrc = r#"{
        "extends": ["eslint:recommended", "plugin:@typescript-eslint/recommended"],
        "rules": {
            // Overrides recommended
            "eqeqeq": "off"
        },
    }"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint"].as_slice()),
    );

    assert!(result.is_ok(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson_presets",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcjson_empty() {
    let biomejson = r#"{ "linter": { "enabled": true } }
"#;
    let eslintrc = r#"{}"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint"].as_slice()),
    );

    assert!(result.is_ok(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson_empty",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcjson_missing_biomejson() {
    let eslintrc = r#"{}"#;

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new(".eslintrc.json").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint"].as_slice()),
    );

    assert!(result.is_err(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcjson_missing_biomejson",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslintrcyaml_unsupported() {
    let biomejson = r#"{}"#;
    let eslintrc = "";

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new(".eslintrc.yaml").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint"].as_slice()),
    );

    assert!(result.is_err(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslintrcyaml_unsupported",
        fs,
        console,
        result,
    ));
}

#[test]
fn migrate_eslint_flat_unsupported() {
    let biomejson = r#"{}"#;
    let eslintrc = "";

    let mut fs = MemoryFileSystem::default();
    fs.insert(Path::new("biome.json").into(), biomejson.as_bytes());
    fs.insert(Path::new("./eslint.config.js").into(), eslintrc.as_bytes());

    let mut console = BufferConsole::default();
    let result = run_cli(
        DynRef::Borrowed(&mut fs),
        &mut console,
        Args::from(["migrate", "eslint"].as_slice()),
    );

    assert!(result.is_err(), "run_cli returned {result:?}");
    assert_cli_snapshot(SnapshotPayload::new(
        module_path!(),
        "migrate_eslint_flat_unsupported",
        fs,
        console,
        result,
    ));
}
