# Changelog

## v0.4.5 
- Initial entry, includes refactor from v0.4.4 and latest regex changes.

## v1.0.6
- duroc_hog no longer scans the output file when repeatedly scanning a directory.
- duroc_hog takes an optional whitelist argument.
- essex_hog added for confluence scanning

## v1.0.7
- refactored a lot of code around entropy matching and filtering. It is now built entirely into lib.rs and thus works with all hogs. It also uses normalized entropy instead of shannon entropy directly. So entropy thresholds are now on a scale of 0-1. The formula is essentially (shannon_entropy / log_base_2(keyspace)). Finding secrets based on entropy is also integrated into all hogs. If you are implementing a custom hog, you should switch from .matches() to .matches_entropy() to get these benefits. 
- changed whitelist to allowlist
- factored the default ruleset into it's own JSON file in src/default_rules.json. This makes it easier for you to modify and customize.
- After the v1.0.7 commits are made, I will upload them to DockerHub and update the README and build scripts in the repo accordingly. This first release will be done manually and future releases should be done via build_ghrelease.sh

## v1.0.8
- reworked allow lists in a few ways:
    - now compiles the values into regular expressions rather than using string compare
    - includes a default allowlist when none is specified
    - if the pattern name "<GLOBAL>" is used it will be checked against all patterns
    - moved the allowlist code into lib.rs so that all hogs will use it by default
    
