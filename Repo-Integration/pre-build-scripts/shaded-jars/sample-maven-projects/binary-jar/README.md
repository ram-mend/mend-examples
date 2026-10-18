# Binary jar sample

A repository holding a shaded jar and no `pom.xml`, as Mend's signature and binary scans see it:
`org.apache.parquet:parquet-jackson` 1.18.0, which bundles three Jackson libraries (see the
[regular sample](../regular/pom.xml)). The jar isn't kept here. To build the sample, download the
published jar into an empty test repository:

    curl -fLO https://repo1.maven.org/maven2/org/apache/parquet/parquet-jackson/1.18.0/parquet-jackson-1.18.0.jar

Its SHA-1 is `414bac539cb2141828051db520f02cd3ed793ab1`. Keep the file name: the hook finds a jar's
own coordinates through the `<artifactId>-<version>.jar` it is named after.
