# Cybersecurity Homelab

An educational security lab by Flavio Giorgio Guarini. The offline SOC example reads a local Suricata EVE JSONL file, converts alerts to SIEM events, and reports related events using the lab's source-IP heuristic. It runs with the Python standard library.

## Try the offline SOC example

Run these commands from the repository root with Python 3:

```sh
cd projects/cybersecurity-homelab
python3 -c 'import json; from csf.soc import LogAnalyzer; print(json.dumps(LogAnalyzer().analyze_logs("examples/suricata.eve.jsonl"), indent=2))'
```

The [synthetic fixture](projects/cybersecurity-homelab/examples/suricata.eve.jsonl) produces two alert events and one grouped incident with a severity of `8.0`. The example uses documentation-only IP addresses and runs without a sensor, server, or network requests. The parser uses the priority in Suricata's [`alert.severity`](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html).

## Run the tests

From `projects/cybersecurity-homelab`, run:

```sh
python3 -m unittest discover -s tests -p test_suricata.py -v
```

The SOC tests cover severity mapping, malformed lines, and the example report. Keep new test inputs synthetic. The repository also contains an experimental API and dashboard for local lab use.

## License

The project under `projects/cybersecurity-homelab` is distributed under its [MIT license](projects/cybersecurity-homelab/LICENSE).
