@IsTest
private class SecurityAuditControllerTest {

    @IsTest
    static void listObjectsReturnsSomething() {
        Test.startTest();
        List<String> objs = SecurityAuditController.listObjects();
        Test.stopTest();
        System.assert(objs != null, 'Expected listObjects to return a list');
        System.assert(objs.size() > 0, 'Expected at least one object');
    }

    @IsTest
    static void listFieldsForAccount() {
        Test.startTest();
        List<String> fields = SecurityAuditController.listFields('Account');
        Test.stopTest();
        System.assert(fields != null, 'Expected fields list');
        System.assert(fields.size() > 0, 'Expected Account to have fields');
    }

    @IsTest
    static void runScanValidatesInput() {
        Boolean threw = false;
        try {
            SecurityAuditController.runScan(null);
        } catch (Exception e) {
            threw = true;
        }
        System.assert(threw, 'Expected runScan to validate null request');
    }
}
