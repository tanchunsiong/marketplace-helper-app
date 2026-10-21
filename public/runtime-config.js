async function applyRuntimeConfig() {
  try {
    const response = await fetch('/api/status', {
      headers: { accept: 'application/json' },
    });
    if (!response.ok) return;

    const config = await response.json();
    for (const element of document.querySelectorAll('[data-runtime-config]')) {
      const value = config[element.dataset.runtimeConfig];
      if (typeof value === 'string' && value) {
        element.textContent = value;
      }
    }
  } catch {
    // The page remains usable if runtime metadata is temporarily unavailable.
  }
}

applyRuntimeConfig();
