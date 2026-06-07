## [0.3.1] - Simulation Slot Fixes and Port Update - 06/07/2026

### Added

### Changed

- Updated the default LogstashAgent port from `9600` to `9650` to avoid conflicts with Logstash monitoring APIs.

### Fixed

- Fixed an import issue that could occur when simulation slots were being deallocated.
- Fixed an issue where simulation slots were not properly evicted when a new pipeline needed to take over an existing slot.
- Fixed simulation flow so slot eviction properly waits for the new pipeline to be backfilled before continuing.

## [0.3.0] - Logstash Agent - ARM Compatibility - 05/14/2026

### Added

- Added ARM Docker image builds to the GitHub Actions workflow after successful test completion.

### Changed

- Incremented the application version number.
- Updated the preferred Logstash Agent version preemptively for the next release.