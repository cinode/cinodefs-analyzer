# CinodeFS analyzer

Simple analyzer binary for exploring CinodeFS graphs.

To execute, run from the root directory:

```bash
go run .
```

Analyzer is available as a http page under <http://localhost:8080/>.

Available options can be found with:

```bash
$ go run . -h

Web server to analyze cinodefs entries.

Usage:
  web_analyzer [flags]

Flags:
  -d, --datastore string    Datastore address (default "https://datastore.cinodenet.org/")
  -e, --entrypoint string   Starting entrypoint (default "9g1R5xUqhAxfHnVBPAyBY9NXNe1dzKK949czZtT9THSMesRk3tKSRTWh2bsaKp4ivFVYyZX3vXMdE74XiAw9ckEWQoKLRouJnn")
  -h, --help                help for web_analyzer
  -p, --port int            Http listen port (default 8080)
```

By default this command points to the CinodeFS graph used by the <https://blog.cinodenet.org/> web page.
