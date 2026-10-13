/* Keep hidden dialogs out of the focus order and lock background scrolling on phones. */
(() => {
  const dialogs = [...document.querySelectorAll('.modal-overlay')];
  const syncDialogs = () => {
    let open = false;
    for (const dialog of dialogs) {
      const active = dialog.classList.contains('active');
      dialog.inert = !active;
      dialog.setAttribute('aria-hidden', String(!active));
      open ||= active;
    }
    document.body.classList.toggle('mobile-modal-open', open);
  };
  for (const dialog of dialogs) {
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    const heading = dialog.querySelector('h2, h3');
    if (heading) {
      if (!heading.id) heading.id = `${dialog.id}-heading`;
      dialog.setAttribute('aria-labelledby', heading.id);
    }
    const close = dialog.querySelector('button');
    if (close && close.textContent.trim() === '×') close.setAttribute('aria-label', '关闭弹窗');
    new MutationObserver(syncDialogs).observe(dialog, { attributes: true, attributeFilter: ['class'] });
  }
  syncDialogs();
})();
