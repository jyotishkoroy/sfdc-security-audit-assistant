import { LightningElement, track } from 'lwc';
import listObjects from '@salesforce/apex/SecurityAuditController.listObjects';
import listFields from '@salesforce/apex/SecurityAuditController.listFields';
import runScanApex from '@salesforce/apex/SecurityAuditController.runScan';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';

export default class SecurityAuditAssistant extends LightningElement {
    @track objectOptions = [];
    @track fieldOptions = [];
    @track findings = [];
    @track error;

    objectApiName;
    fieldApiNames = [];
    isLoading = false;

    columns = [
        { label: 'Category', fieldName: 'category' },
        { label: 'Severity', fieldName: 'severity' },
        { label: 'Object', fieldName: 'objectApiName' },
        { label: 'Field', fieldName: 'fieldApiName' },
        { label: 'Finding', fieldName: 'message', wrapText: true },
        { label: 'Recommendation', fieldName: 'recommendation', wrapText: true }
    ];

    get runDisabled() {
        return !this.objectApiName || this.isLoading;
    }

    get exportDisabled() {
        return !this.findings || this.findings.length === 0;
    }

    get statusText() {
        if (!this.objectApiName) return 'Select an object to begin.';
        if (this.isLoading) return 'Running scan...';
        if (this.findings?.length) return `${this.findings.length} finding(s)`;
        return 'Ready.';
    }

    connectedCallback() {
        this.loadObjects();
    }

    async loadObjects() {
        this.isLoading = true;
        try {
            const objs = await listObjects();
            this.objectOptions = (objs || []).map((o) => ({ label: o, value: o }));
            this.error = undefined;
        } catch (e) {
            this.error = this.normalizeError(e);
        } finally {
            this.isLoading = false;
        }
    }

    async handleObjectChange(event) {
        this.objectApiName = event.detail.value;
        this.fieldApiNames = [];
        this.findings = [];
        this.error = undefined;

        this.isLoading = true;
        try {
            const fields = await listFields({ objectApiName: this.objectApiName });
            this.fieldOptions = (fields || []).map((f) => ({ label: f, value: f }));
        } catch (e) {
            this.error = this.normalizeError(e);
        } finally {
            this.isLoading = false;
        }
    }

    handleFieldChange(event) {
        this.fieldApiNames = event.detail.value;
    }

    async runScan() {
        this.error = undefined;
        this.findings = [];
        this.isLoading = true;

        try {
            const req = {
                objectApiName: this.objectApiName,
                fieldApiNames: this.fieldApiNames
            };

            const res = await runScanApex({ req });
            const rows = (res || []).map((r, i) => ({ key: `${i}-${r.category}-${r.severity}`, ...r }));
            this.findings = rows;

            const high = rows.filter((x) => x.severity === 'High').length;
            const med = rows.filter((x) => x.severity === 'Medium').length;
            const low = rows.filter((x) => x.severity === 'Low').length;

            this.toast('Scan complete', `High: ${high}, Medium: ${med}, Low: ${low}`, high ? 'warning' : 'success');
        } catch (e) {
            this.error = this.normalizeError(e);
            this.toast('Scan failed', this.error, 'error');
        } finally {
            this.isLoading = false;
        }
    }

    exportCsv() {
        const headers = ['Category', 'Severity', 'Object', 'Field', 'Finding', 'Recommendation'];
        const esc = (v) => {
            const s = (v ?? '').toString().replaceAll('"', '""');
            return `"${s}"`;
        };

        const lines = [headers.join(',')];
        (this.findings || []).forEach((r) => {
            lines.push([
                esc(r.category),
                esc(r.severity),
                esc(r.objectApiName),
                esc(r.fieldApiName || ''),
                esc(r.message),
                esc(r.recommendation)
            ].join(','));
        });

        const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `security-audit-${this.objectApiName || 'report'}.csv`;
        a.click();
        URL.revokeObjectURL(url);

        this.toast('Exported', 'CSV downloaded.', 'success');
    }

    toast(title, message, variant) {
        this.dispatchEvent(new ShowToastEvent({ title, message, variant }));
    }

    normalizeError(e) {
        if (!e) return 'Unknown error';
        if (typeof e === 'string') return e;
        if (e.body) {
            if (Array.isArray(e.body)) return e.body.map((x) => x.message).join(', ');
            return e.body.message || JSON.stringify(e.body);
        }
        return e.message || JSON.stringify(e);
    }
}
