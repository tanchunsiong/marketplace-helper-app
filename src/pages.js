import fs from 'node:fs/promises';
import path from 'node:path';

const PAGES = new Set(['index', 'docs', 'privacy', 'terms', 'security', 'support']);

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  ));
}

function initialsFor(name) {
  const letters = name.split(/\s+/).map((word) => word.match(/[\p{L}\p{N}]/u)?.[0]).filter(Boolean);
  return (letters.length > 1 ? letters.slice(0, 2).join('') : name.replace(/[^\p{L}\p{N}]/gu, '').slice(0, 2)).toUpperCase();
}

// Branding and policy text come from the environment so the pages carry no
// operator-specific content in the repository.
export function pageSettings(env = process.env, now = new Date()) {
  const appName = env.APP_NAME?.trim() || 'Marketplace Helper';
  return {
    APP_NAME: appName,
    APP_INITIALS: initialsFor(appName),
    YEAR: String(now.getUTCFullYear()),
    SUPPORT_HOURS: env.SUPPORT_HOURS?.trim() || 'Support requests are reviewed during business hours.',
    POLICY_EFFECTIVE_DATE: env.POLICY_EFFECTIVE_DATE?.trim() || '',
  };
}

export function renderPage(html, settings) {
  let output = html;
  if (!settings.POLICY_EFFECTIVE_DATE) {
    // Omit the effective-date line entirely when no date is configured.
    output = output.replace(/[ \t]*<p>[^<]*\{\{POLICY_EFFECTIVE_DATE\}\}[^<]*<\/p>\n?/g, '');
  }
  return output.replace(/\{\{([A-Z_]+)\}\}/g, (match, key) => (
    key in settings ? escapeHtml(settings[key]) : match
  ));
}

export function templatedPages({ publicDir = 'public', env = process.env } = {}) {
  return async (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    const name = req.path === '/' ? 'index' : req.path.replace(/^\//, '').replace(/\.html$/, '');
    if (!PAGES.has(name)) return next();
    try {
      const html = await fs.readFile(path.join(publicDir, `${name}.html`), 'utf8');
      return res.type('html').send(renderPage(html, pageSettings(env)));
    } catch (error) {
      if (error.code === 'ENOENT') return next();
      return next(error);
    }
  };
}
