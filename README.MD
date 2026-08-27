# Windows Self Cleaning Library

This library is a single include header to clear recent execution traces

### Supported traces

- UserAssist
- RecentFiles
- RunMRU
- Automatic/CustomDestinations
- RecentDocs
- Prefetch
- USNJournal (Just full deletion, not arbitrary files)
- Amcache
- System BAM/DAM
- MuiCache
- Explorer FeatureUsage
- Compatibility Assistant (registry and PCA launch dictionaries)
- Shellbags (matching BagMRU branch only)
- NVIDIA recent programs (`nvAppTimestamps`)
- Shimcache (Windows 10/11 `10ts` entries)
- Windows Error Reporting (`ReportQueue`, `ReportArchive`, `ReportStore`)

### TODO

- SRUM contains exeuction traces and network traces of the app

SRUM remains pending because its live `SRUDB.dat` is a service-owned ESE
database. Deleting the database or stopping diagnostics and editing it without
a transaction-safe, version-independent schema would remove unrelated system
history and can leave the database dirty.

The new cleaners are selective: unknown binary formats fail without writing,
and unrelated registry values, NVIDIA records and Shimcache entries are kept.
