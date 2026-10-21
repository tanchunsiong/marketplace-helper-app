import test from 'node:test';
import assert from 'node:assert/strict';
import { pageSettings, renderPage } from '../src/pages.js';

test('renders configured branding and escapes values', () => {
  const settings = pageSettings({ APP_NAME: 'Acme <Builder>', POLICY_EFFECTIVE_DATE: 'January 1, 2027' }, new Date('2027-03-01T00:00:00Z'));
  const html = renderPage('<h1>{{APP_NAME}}</h1><i>{{APP_INITIALS}}</i><p>Effective date: {{POLICY_EFFECTIVE_DATE}}.</p> {{YEAR}}', settings);
  assert.equal(html, '<h1>Acme &lt;Builder&gt;</h1><i>AB</i><p>Effective date: January 1, 2027.</p> 2027');
});

test('uses neutral defaults and omits an unset effective date', () => {
  const settings = pageSettings({}, new Date('2027-03-01T00:00:00Z'));
  const html = renderPage('<p>Effective date: {{POLICY_EFFECTIVE_DATE}}.</p>\n<b>{{APP_NAME}}</b> {{SUPPORT_HOURS}}', settings);
  assert.equal(html, '<b>Marketplace Helper</b> Support requests are reviewed during business hours.');
});

test('leaves unknown placeholders untouched', () => {
  assert.equal(renderPage('{{UNKNOWN}}', pageSettings({})), '{{UNKNOWN}}');
});
