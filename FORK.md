# Breaking-IT k6 fork

This repository is a modified version of [Grafana k6](https://github.com/grafana/k6).
Breaking-IT maintains it for use with BreakTest's load-generation integrations.

## License

The complete work, including the Breaking-IT modifications, is licensed under the
[GNU Affero General Public License, version 3](LICENSE.md). The original copyright and
license notices are retained.

## Source releases

The `breakingit` branch contains the current fork source. Immutable source-release tags are
published for distributed builds. The initial public release is
[`breakingit-v2.1.0-26`](https://github.com/Breaking-IT/k6/tree/breakingit-v2.1.0-26).

Each BreakTest release that contains this component should identify the corresponding immutable
tag or commit in this repository. Build and deployment tooling must not add proprietary source
code to the k6 executable.

## Fork-specific changes

- Adds the `timescaledb-breakingit` output for writing load-test data through a PG-proxy.
- Adds optional detailed request and response data for failed HTTP requests.
- Extends browser network and error metrics, including optional error screenshots.
- Adds the `lean` build tag used for smaller cloud-free release binaries.
- Adds Breaking-IT build helpers and operational configuration.

For the complete change history, compare the `breakingit` branch with the upstream
[grafana/k6](https://github.com/grafana/k6) repository.
