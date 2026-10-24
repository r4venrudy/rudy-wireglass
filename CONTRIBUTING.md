# Contributing

Thanks for helping improve Wireglass. Keep packet parsing bounds-checked, resource limits explicit, and output reproducible.

1. Build with CMake 3.20+ and a C11 compiler.
2. Add a regression fixture for parser or report changes. Prefer small generated captures over real traffic.
3. Run `cmake --build build` and `ctest --test-dir build --output-on-failure`.
4. Document format or heuristic changes and note their limitations.

Please do not submit captures containing private or customer traffic. Sanitized synthetic fixtures are preferred.
