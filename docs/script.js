const menuButton = document.querySelector('.menu-toggle');
const siteNav = document.querySelector('#site-nav');
menuButton?.addEventListener('click', () => {
  const open = menuButton.getAttribute('aria-expanded') !== 'true';
  menuButton.setAttribute('aria-expanded', String(open));
  siteNav.classList.toggle('open', open);
});
siteNav?.addEventListener('click', (event) => {
  if (event.target.closest('a')) {
    siteNav.classList.remove('open');
    menuButton.setAttribute('aria-expanded', 'false');
  }
});
document.querySelector('.copy-button')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const command = document.querySelector(button.dataset.copy)?.textContent;
  if (!command) return;
  try {
    await navigator.clipboard.writeText(command);
    button.textContent = 'Copied';
    window.setTimeout(() => { button.textContent = 'Copy'; }, 2000);
  } catch {
    button.textContent = 'Select text';
    window.setTimeout(() => { button.textContent = 'Copy'; }, 2000);
  }
});
