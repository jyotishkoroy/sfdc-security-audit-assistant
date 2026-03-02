import { createElement } from 'lwc';
import SecurityAuditAssistant from 'c/securityAuditAssistant';

jest.mock('@salesforce/apex/SecurityAuditController.listObjects', () => ({ default: jest.fn() }), { virtual: true });
jest.mock('@salesforce/apex/SecurityAuditController.listFields', () => ({ default: jest.fn() }), { virtual: true });
jest.mock('@salesforce/apex/SecurityAuditController.runScan', () => ({ default: jest.fn() }), { virtual: true });

import listObjects from '@salesforce/apex/SecurityAuditController.listObjects';
import listFields from '@salesforce/apex/SecurityAuditController.listFields';
import runScan from '@salesforce/apex/SecurityAuditController.runScan';

const flushPromises = () => new Promise(setImmediate);

describe('c-security-audit-assistant', () => {
    afterEach(() => {
        while (document.body.firstChild) {
            document.body.removeChild(document.body.firstChild);
        }
        jest.clearAllMocks();
    });

    it('loads object options on init', async () => {
        listObjects.mockResolvedValue(['Account', 'Contact']);

        const element = createElement('c-security-audit-assistant', { is: SecurityAuditAssistant });
        document.body.appendChild(element);
        await flushPromises();

        expect(listObjects).toHaveBeenCalled();
        expect(element.objectOptions.length).toBe(2);
    });

    it('runs scan and populates findings', async () => {
        listObjects.mockResolvedValue(['Account']);
        listFields.mockResolvedValue(['Name']);
        runScan.mockResolvedValue([
            { category: 'Sharing', severity: 'High', objectApiName: 'Account', fieldApiName: null, message: 'OWD is ReadWrite', recommendation: 'Make Private' }
        ]);

        const element = createElement('c-security-audit-assistant', { is: SecurityAuditAssistant });
        document.body.appendChild(element);
        await flushPromises();

        // select object
        element.objectApiName = 'Account';
        await element.runScan();
        await flushPromises();

        expect(runScan).toHaveBeenCalled();
        expect(element.findings.length).toBe(1);
    });
});
