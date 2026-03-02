public with sharing class SecurityAuditController {

    public class ScanRequest {
        @AuraEnabled public String objectApiName;
        @AuraEnabled public List<String> fieldApiNames;
        @AuraEnabled public Integer limitSize;
    }

    public class Finding {
        @AuraEnabled public String category;        // CRUD / FLS / Sharing
        @AuraEnabled public String severity;        // Low / Medium / High
        @AuraEnabled public String objectApiName;
        @AuraEnabled public String fieldApiName;    // optional
        @AuraEnabled public String message;
        @AuraEnabled public String recommendation;
    }

    private class SensitiveConfig {
        String objectApiName;
        String fieldApiName;
        String severity;
        String notes;
    }

    @AuraEnabled(cacheable=true)
    public static List<String> listObjects() {
        List<String> names = new List<String>();
        Map<String, Schema.SObjectType> gd = Schema.getGlobalDescribe();

        for (String k : gd.keySet()) {
            Schema.DescribeSObjectResult d = gd.get(k).getDescribe();
            // Keep it usable in UI: only objects visible to user and not overly noisy.
            if (!d.isAccessible()) continue;
            if (d.isDeprecatedAndHidden()) continue;
            if (k.endsWith('__History') || k.endsWith('__Share')) continue;
            names.add(k);
        }
        names.sort();
        return names;
    }

    @AuraEnabled(cacheable=true)
    public static List<String> listFields(String objectApiName) {
        if (String.isBlank(objectApiName)) return new List<String>();
        Schema.DescribeSObjectResult d = Schema.getGlobalDescribe().get(objectApiName).getDescribe();
        Map<String, Schema.SObjectField> f = d.fields.getMap();

        List<String> out = new List<String>();
        for (String name : f.keySet()) {
            Schema.DescribeFieldResult fd = f.get(name).getDescribe();
            if (fd.isCalculated()) continue;
            if (fd.getType() == Schema.DisplayType.Address) continue;
            out.add(name);
        }
        out.sort();
        return out;
    }

    @AuraEnabled(cacheable=true)
    public static List<Security_Audit_Sensitive_Field__mdt> getSensitiveConfig(String objectApiName) {
        if (String.isBlank(objectApiName)) return new List<Security_Audit_Sensitive_Field__mdt>();
        return [
            SELECT DeveloperName, MasterLabel, ObjectApiName__c, FieldApiName__c, Severity__c, Notes__c
            FROM Security_Audit_Sensitive_Field__mdt
            WHERE ObjectApiName__c = :objectApiName
        ];
    }

    @AuraEnabled
    public static List<Finding> runScan(ScanRequest req) {
        if (req == null || String.isBlank(req.objectApiName)) {
            throw new AuraHandledException('Object API name is required.');
        }

        Map<String, Schema.SObjectType> gd = Schema.getGlobalDescribe();
        if (!gd.containsKey(req.objectApiName)) {
            throw new AuraHandledException('Unknown object: ' + req.objectApiName);
        }

        Schema.DescribeSObjectResult od = gd.get(req.objectApiName).getDescribe();

        List<SensitiveConfig> configs = loadSensitive(req.objectApiName);
        Boolean objectSensitive = false;
        String objectSensitivity = 'Medium';
        String objectNotes = null;

        Set<String> sensitiveFields = new Set<String>();
        Map<String, String> fieldSeverity = new Map<String, String>();
        for (SensitiveConfig c : configs) {
            if (String.isBlank(c.fieldApiName)) {
                objectSensitive = true;
                objectSensitivity = c.severity;
                objectNotes = c.notes;
            } else {
                sensitiveFields.add(c.fieldApiName);
                fieldSeverity.put(c.fieldApiName, c.severity);
            }
        }

        List<Finding> findings = new List<Finding>();

        // Sharing sanity checks
        if (objectSensitive) {
            Schema.SharingModel sm = od.getSharingModel();
            // External sharing model exists as well, but not all objects support it consistently; keep simple.
            if (sm == Schema.SharingModel.ReadWrite || sm == Schema.SharingModel.ReadWriteTransfer) {
                findings.add(makeFinding('Sharing', 'High', req.objectApiName, null,
                    'OWD is ' + String.valueOf(sm) + ' for a sensitive object.',
                    'Consider Private/Read and use criteria-based sharing rules for exceptions.'
                ));
            } else if (sm == Schema.SharingModel.Read) {
                findings.add(makeFinding('Sharing', 'Medium', req.objectApiName, null,
                    'OWD is Read for a sensitive object.',
                    'Confirm if Read should be restricted to Private and shared selectively.'
                ));
            } else {
                findings.add(makeFinding('Sharing', 'Low', req.objectApiName, null,
                    'OWD is ' + String.valueOf(sm) + ' for a sensitive object.',
                    'No action required if aligned with data policy.'
                ));
            }
        }

        // CRUD checks (effective access)
        if (objectSensitive) {
            if (od.isDeletable()) {
                findings.add(makeFinding('CRUD', pickSeverity(objectSensitivity, 'High'), req.objectApiName, null,
                    'Delete permission is enabled (effective access) for sensitive object.',
                    'Remove delete from broad access; gate via permission set or approval process.'
                ));
            }
            if (od.isCreateable()) {
                findings.add(makeFinding('CRUD', pickSeverity(objectSensitivity, 'Medium'), req.objectApiName, null,
                    'Create permission is enabled (effective access) for sensitive object.',
                    'Confirm create should be limited; consider restricting to specific roles.'
                ));
            }
            if (od.isUpdateable()) {
                findings.add(makeFinding('CRUD', pickSeverity(objectSensitivity, 'Medium'), req.objectApiName, null,
                    'Edit permission is enabled (effective access) for sensitive object.',
                    'Confirm edit should be limited; consider field-level restrictions and sharing.'
                ));
            }
        }

        // FLS checks (effective access)
        List<String> fieldsToCheck = (req.fieldApiNames == null) ? new List<String>() : req.fieldApiNames;
        if (fieldsToCheck.isEmpty()) {
            // If user didn't pick fields, check only fields marked sensitive in CMDT.
            fieldsToCheck.addAll(sensitiveFields);
        }

        Map<String, Schema.SObjectField> fmap = od.fields.getMap();
        for (String f : fieldsToCheck) {
            if (!fmap.containsKey(f)) continue;
            Schema.DescribeFieldResult fd = fmap.get(f).getDescribe();

            Boolean markedSensitive = sensitiveFields.contains(f) || objectSensitive;
            String sev = fieldSeverity.containsKey(f) ? fieldSeverity.get(f) : objectSensitivity;

            if (markedSensitive && fd.isUpdateable()) {
                findings.add(makeFinding('FLS', pickSeverity(sev, 'High'), req.objectApiName, f,
                    'Field is editable for current user on a sensitive field.',
                    'Restrict edit access with FLS; use separate permission set for break-glass edits.'
                ));
            } else if (markedSensitive && fd.isAccessible() && !fd.isUpdateable()) {
                findings.add(makeFinding('FLS', pickSeverity(sev, 'Medium'), req.objectApiName, f,
                    'Field is readable for current user on a sensitive field.',
                    'Confirm read access is appropriate; consider masking/encryption where needed.'
                ));
            }
        }

        // Add config notes as informational item
        if (objectSensitive && !String.isBlank(objectNotes)) {
            findings.add(makeFinding('Config', 'Low', req.objectApiName, null,
                'Sensitivity note: ' + objectNotes,
                'Keep config aligned with data classification.'
            ));
        }

        return findings;
    }

    private static List<SensitiveConfig> loadSensitive(String objectApiName) {
        List<SensitiveConfig> out = new List<SensitiveConfig>();
        for (Security_Audit_Sensitive_Field__mdt m : [
            SELECT ObjectApiName__c, FieldApiName__c, Severity__c, Notes__c
            FROM Security_Audit_Sensitive_Field__mdt
            WHERE ObjectApiName__c = :objectApiName
        ]) {
            SensitiveConfig c = new SensitiveConfig();
            c.objectApiName = m.ObjectApiName__c;
            c.fieldApiName = m.FieldApiName__c;
            c.severity = String.isBlank(m.Severity__c) ? 'Medium' : m.Severity__c;
            c.notes = m.Notes__c;
            out.add(c);
        }
        return out;
    }

    private static Finding makeFinding(String category, String severity, String obj, String field, String msg, String rec) {
        Finding f = new Finding();
        f.category = category;
        f.severity = severity;
        f.objectApiName = obj;
        f.fieldApiName = field;
        f.message = msg;
        f.recommendation = rec;
        return f;
    }

    private static String pickSeverity(String base, String desired) {
        // Escalate severity between base and desired in a predictable way.
        List<String> order = new List<String>{'Low','Medium','High'};
        Integer b = order.indexOf(String.isBlank(base) ? 'Medium' : base);
        Integer d = order.indexOf(desired);
        Integer idx = Math.max(b, d);
        return order[idx];
    }
}
