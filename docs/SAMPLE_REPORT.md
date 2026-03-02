# Sample report (illustrative)

| Category | Severity | Object | Field | Finding | Recommendation |
|---|---:|---|---|---|---|
| Sharing | High | Account |  | OWD is ReadWrite for sensitive object | Consider Private/Read and use sharing rules |
| FLS | High | Contact | SSN__c | Field is editable for current user | Restrict FLS or move to shield/encrypted field |
| CRUD | Medium | Case |  | Delete permission enabled for sensitive object | Remove delete or gate via permission set |
