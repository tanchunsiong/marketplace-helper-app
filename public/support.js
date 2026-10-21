const form = document.querySelector('#support-form');
const status = document.querySelector('#support-status');
const startedAt = document.querySelector('#support-started-at');

startedAt.value = String(Date.now());

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  status.textContent = 'Submitting request...';
  status.dataset.state = '';

  try {
    const response = await fetch(form.action, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(response.status === 429
        ? 'Too many requests. Wait at least one hour before trying again.'
        : 'The request could not be submitted. Check the fields and try again.');
    }
    form.reset();
    startedAt.value = String(Date.now());
    status.textContent = `Request received. Reference: ${result.request_id}`;
    status.dataset.state = 'success';
  } catch (error) {
    status.textContent = error.message;
    status.dataset.state = 'error';
  } finally {
    button.disabled = false;
  }
});
