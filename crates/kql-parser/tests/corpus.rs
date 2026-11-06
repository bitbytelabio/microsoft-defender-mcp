//! Advanced Hunting queries in the style of Microsoft's public hunting samples: each must parse, and
//! the analysis must name exactly the tables it reads.

use kql_parser::{analyze, parse};

fn tables(q: &str) -> Vec<String> {
    let a = analyze(q).unwrap_or_else(|e| panic!("{e}\n---\n{q}"));
    a.tables.into_iter().collect()
}

#[test]
fn hunting_queries_parse_with_their_tables() {
    let cases: &[(&str, &[&str])] = &[
        (
            "DeviceProcessEvents\n| where FileName =~ 'powershell.exe' and ProcessCommandLine has_any ('-enc', '-EncodedCommand')\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, ReportId",
            &["DeviceProcessEvents"],
        ),
        (
            "// encoded PowerShell, last 7 days\nDeviceProcessEvents\n| where Timestamp > ago(7d) // window\n| where InitiatingProcessFileName !~ 'explorer.exe'\n| summarize Count = count(), Hosts = dcount(DeviceId) by FileName, bin(Timestamp, 1h)\n| order by Count desc\n| take 100",
            &["DeviceProcessEvents"],
        ),
        (
            "let ips = dynamic(['203.0.113.5', '198.51.100.7']);\nDeviceNetworkEvents\n| where RemoteIP in (ips) or RemoteUrl has_any (ips)\n| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName",
            &["DeviceNetworkEvents"],
        ),
        (
            "let lookback = 14d;\nlet suspicious = DeviceProcessEvents\n    | where Timestamp > ago(lookback)\n    | where ProcessCommandLine contains \"vssadmin\" and ProcessCommandLine contains \"delete shadows\";\nsuspicious\n| join kind=inner (DeviceNetworkEvents | where RemotePort in (445, 139)) on DeviceId\n| project-away DeviceId1",
            &["DeviceNetworkEvents", "DeviceProcessEvents"],
        ),
        (
            "DeviceFileEvents\n| where SHA256 in~ (\"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\")\n| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId | project DeviceId, OSPlatform) on $left.DeviceId == $right.DeviceId\n| extend Dir = tostring(split(FolderPath, @'\\')[0])",
            &["DeviceFileEvents", "DeviceInfo"],
        ),
        (
            "EmailEvents\n| where Timestamp between (ago(2d) .. now())\n| where SenderFromDomain endswith \".example\" and DeliveryAction == \"Delivered\"\n| lookup kind=leftouter EmailUrlInfo on NetworkMessageId\n| summarize Urls = make_set(Url, 50) by NetworkMessageId, RecipientEmailAddress",
            &["EmailEvents", "EmailUrlInfo"],
        ),
        (
            "union DeviceProcessEvents, DeviceFileEvents, (DeviceRegistryEvents | where ActionType == 'RegistryValueSet')\n| where InitiatingProcessCommandLine matches regex @'(?i)rundll32.+javascript:'\n| count",
            &[
                "DeviceFileEvents",
                "DeviceProcessEvents",
                "DeviceRegistryEvents",
            ],
        ),
        (
            "IdentityLogonEvents\n| where ActionType == 'LogonFailed' and isnotempty(AccountUpn)\n| summarize Failures = count() by AccountUpn, bin(Timestamp, 10m)\n| where Failures > 20\n| top 10 by Failures desc nulls last",
            &["IdentityLogonEvents"],
        ),
        (
            "DeviceEvents\n| where ActionType == 'AntivirusDetection'\n| extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName), Sev = AdditionalFields['Severity']\n| where ThreatName !has 'Test' and ThreatName !contains_cs 'EICAR'\n| distinct DeviceName, ThreatName",
            &["DeviceEvents"],
        ),
        (
            "DeviceTvmSoftwareVulnerabilities\n| where CveId in ('CVE-2026-1234', 'CVE-2026-5678')\n| summarize Devices = dcount(DeviceId), Versions = make_set(SoftwareVersion) by SoftwareName, CveId\n| sort by Devices desc",
            &["DeviceTvmSoftwareVulnerabilities"],
        ),
        (
            "AlertInfo\n| where Timestamp > ago(1d) and Severity in ('High', 'Medium')\n| join AlertEvidence on AlertId\n| where EntityType == 'Ip'\n| project Timestamp, Title, RemoteIP, AttackTechniques\n| mv-expand Technique = todynamic(AttackTechniques) to typeof(string)\n| where Technique startswith 'T1059'",
            &["AlertEvidence", "AlertInfo"],
        ),
        (
            "DeviceProcessEvents\n| where FileName in~ ('certutil.exe') and ProcessCommandLine has_all ('-urlcache', 'http')\n| parse ProcessCommandLine with * 'http' Url:string ' ' *\n| extend Domain = extract(@'https?://([^/]+)', 1, Url)\n| project-rename Host = DeviceName\n| project-reorder Timestamp, Host",
            &["DeviceProcessEvents"],
        ),
        (
            "CloudAppEvents\n| where ActionType == 'FileDownloaded' and Timestamp > datetime(2026-11-01T00:00:00Z)\n| evaluate bag_unpack(RawEventData)\n| summarize n = count() by AccountDisplayName\n| where n > toscalar(CloudAppEvents | summarize avg = avg(1.0) | project avg)",
            &["CloudAppEvents"],
        ),
        (
            "let window = 1h;\nlet f = (name:string) { DeviceProcessEvents | where FileName =~ name };\nf('mshta.exe')\n| where Timestamp > ago(window)\n| make-series n = count() default = 0 on Timestamp from ago(1d) to now() step 1h by DeviceName",
            &["DeviceProcessEvents"],
        ),
        (
            "DeviceLogonEvents\n| where LogonType == \"RemoteInteractive\" and not(RemoteIP startswith '10.')\n| extend Hour = hourofday(Timestamp), IsNight = iff(hourofday(Timestamp) < 6, true, false)\n| where IsNight\n| summarize by DeviceName, AccountName, RemoteIP;",
            &["DeviceLogonEvents"],
        ),
        (
            "DeviceNetworkEvents\n| where RemotePort == 3389 and ActionType == 'ConnectionSuccess'\n| summarize Targets = dcount(RemoteIP), First = min(Timestamp), Last = max(Timestamp) by DeviceName, InitiatingProcessAccountName\n| where Targets >= 5\n| extend Span = Last - First\n| where Span < 30m",
            &["DeviceNetworkEvents"],
        ),
        (
            "DeviceImageLoadEvents\n| where FileName =~ 'samlib.dll' and not(InitiatingProcessFolderPath startswith @'C:\\Windows\\System32')\n| mv-apply Path = split(InitiatingProcessFolderPath, '\\\\') on (summarize Depth = count())\n| sample 10",
            &["DeviceImageLoadEvents"],
        ),
        (
            "UrlClickEvents\n| where Url has 'login' and IsClickedThrough == true\n| where ActionType in ('ClickAllowed', 'UrlScanInProgress')\n| project Timestamp, AccountUpn, Url, ['Workload']",
            &["UrlClickEvents"],
        ),
        (
            "IdentityInfo\n| summarize arg_max(Timestamp, *) by AccountObjectId\n| where Department == 'Finance'\n| join kind=rightsemi (AADSignInEventsBeta | where ErrorCode == 0 and Country !in ('VN', 'SG')) on AccountObjectId",
            &["AADSignInEventsBeta", "IdentityInfo"],
        ),
        (
            "DeviceRegistryEvents\n| where RegistryKey has @'\\CurrentVersion\\Run' and RegistryValueData has_cs 'AppData'\n| where Timestamp > ago(3d)\n| serialize\n| extend Prev = prev(RegistryValueData)\n| project-keep Timestamp, Device*, Registry*",
            &["DeviceRegistryEvents"],
        ),
        ("print x = 1, y = 'a'\n| extend z = x * 2 + 1", &[]),
        (
            "range Hour from ago(1d) to now() step 1h\n| join kind=leftouter (DeviceProcessEvents | summarize n = count() by Hour = bin(Timestamp, 1h)) on Hour",
            &["DeviceProcessEvents"],
        ),
        (
            "datatable (Name:string, Score:long) ['a', 1, 'b', 2,]\n| where Score > 1",
            &[],
        ),
    ];
    for (q, want) in cases {
        assert_eq!(
            tables(q),
            want.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "{q}"
        );
    }
}

#[test]
fn reports_reach_outside_the_tenant() {
    let a = analyze("cluster('help').database('Samples').StormEvents | take 10").unwrap();
    assert!(a.cross_cluster);
    let a = analyze("externaldata (x:string) [@'https://e.example/x.csv'] with (format='csv')")
        .unwrap();
    assert!(a.external_data);
    let a = analyze("external_table('t') | take 1").unwrap();
    assert!(a.external_data);
    let a = analyze("evaluate http_request('https://e.example')").unwrap();
    assert!(a.plugins.contains("http_request"));
    let a = analyze("set notruncation;\nDeviceInfo | take 1").unwrap();
    assert!(a.set_options.contains("notruncation"));
    let a = analyze("search \"mimikatz\"").unwrap();
    assert!(a.unscoped_search);
    let a = analyze("search in (DeviceProcessEvents) ProcessCommandLine:\"mimikatz\"").unwrap();
    assert!(!a.unscoped_search);
    assert!(a.tables.contains("DeviceProcessEvents"));
    let a = analyze("union withsource=T Device*\n| take 1").unwrap();
    assert!(a.table_patterns.contains("Device*"));
    let a = analyze("table('DeviceInfo') | take 1").unwrap();
    assert!(a.tables.contains("DeviceInfo"));
    let a = analyze("DeviceInfo | invoke FileProfile()").unwrap();
    assert!(a.invoked.contains("FileProfile"));
}

#[test]
fn column_names_are_not_tables() {
    // Function arguments and `in` lists hold columns and let-bound values, not tables.
    let a = analyze("let names = dynamic(['a']);\nDeviceProcessEvents | where FileName in (names) and tolower(ProcessCommandLine) has 'x' | where InitiatingProcessId in (ProcessId)").unwrap();
    assert_eq!(
        a.tables.into_iter().collect::<Vec<_>>(),
        vec!["DeviceProcessEvents".to_string()]
    );
    // ... unless they are piped: then the source is a table.
    let a = analyze("DeviceProcessEvents | where DeviceId in ((DeviceInfo | where OSPlatform == 'Linux' | project DeviceId))").unwrap();
    assert!(a.tables.contains("DeviceInfo"));
}

#[test]
fn refuses_what_it_does_not_understand() {
    for q in [
        ".show tables",
        "DeviceProcessEvents | frobnicate x",
        "DeviceProcessEvents | where",
        "DeviceProcessEvents | where FileName == 'unterminated",
        "DeviceProcessEvents | take 10 | ",
        "DeviceProcessEvents; | take 1",
    ] {
        let e = parse(q).expect_err(q);
        assert!(e.line >= 1 && e.column >= 1, "{q}: {e}");
    }
    let e = parse("DeviceProcessEvents\n| where X == 1\n| frobnicate").unwrap_err();
    assert_eq!(e.line, 3, "{e}");
}

#[test]
fn more_operators_and_expressions_parse() {
    for q in [
        "DeviceInfo | where A == 'x' and B != 'y' or C <> 'z' and not(D)",
        "DeviceInfo | where X !in ('a', 'b') and Y !in~ ('c') and Z between (1..5) and W !between (1 .. 5)",
        "DeviceInfo | where * has 'mimikatz'",
        "DeviceInfo | where Timestamp > ago(1.5h) and Timestamp < now(-5min) and Delta > 100ms and Big > 1e5 and Hex == 0x1F",
        "DeviceInfo | where OSPlatform like 'Windows%' and Name notlike 'x'",
        "DeviceInfo | top-hitters 5 of OSPlatform",
        "DeviceInfo | sample-distinct 5 of DeviceName",
        "DeviceInfo | summarize count() by OSPlatform | render timechart with (title='x')",
        "DeviceInfo | getschema",
        "DeviceInfo | as hint.materialized=true T | where 1 == 1",
        "DeviceInfo | parse-where kind=regex DeviceName with '(?<n>[a-z]+)' n:string",
        "DeviceInfo | parse-kv AdditionalFields as (a:string, b:long) with (pair_delimiter=',', kv_delimiter='=')",
        "DeviceInfo | extend d = dynamic({\"a\": [1, 2.5, 'x', null], \"b\": {\"c\": true}}), t = typeof(string), g = guid(74be27de-1e4e-49d9-b579-fe0b331d3642)",
        "DeviceInfo | extend (rsquare, slope) = series_fit_line(y)",
        "DeviceInfo | summarize hint.strategy=shuffle kind = count() by OSPlatform",
        "DeviceInfo | distinct *",
        "DeviceInfo | where H == h'secret' and V == @\"C:\\\"\"x\" and M == ```multi\nline```",
        "let T = view () { DeviceInfo | take 1 };\nT | count",
        "DeviceInfo | mv-expand kind=array with_itemindex=i Tags limit 10",
        "DeviceInfo | where DeviceName has_cs 'X' and DeviceName !hasprefix 'y' and DeviceName hassuffix_cs 'z' and DeviceName contains_cs 'q'",
    ] {
        if let Err(e) = parse(q) {
            panic!("{e}\n---\n{q}");
        }
    }
}
