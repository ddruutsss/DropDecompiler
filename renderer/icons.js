// Line icons (16px grid, 1.5px stroke). icon(name) returns SVG markup; elements with data-icon get theirs
// prepended on load.
const ICON_PATHS = {
  plus: '<path d="M8 3.5v9M3.5 8h9"/>',
  upload: '<path d="M8 10.5V3M5 6l3-3 3 3"/><path d="M2.75 10.5v1.75c0 .55.45 1 1 1h8.5c.55 0 1-.45 1-1V10.5"/>',
  download: '<path d="M8 2.75v7.5M5 7.5l3 3 3-3"/><path d="M2.75 10.5v1.75c0 .55.45 1 1 1h8.5c.55 0 1-.45 1-1V10.5"/>',
  folder: '<path d="M2.25 4.25c0-.55.45-1 1-1h3l1.5 1.5h5c.55 0 1 .45 1 1v6c0 .55-.45 1-1 1h-9.5c-.55 0-1-.45-1-1z"/>',
  folderOpen: '<path d="M2.25 11.75V4.25c0-.55.45-1 1-1h3l1.5 1.5h4.5c.55 0 1 .45 1 1V7"/><path d="M2.25 11.75 4 7.5c.15-.3.45-.5.8-.5h8.7c.35 0 .6.35.45.7l-1.6 3.9c-.15.3-.45.5-.8.5H2.25"/>',
  file: '<path d="M4.25 1.75h4.5l3 3v8.5c0 .55-.45 1-1 1h-6.5c-.55 0-1-.45-1-1v-10.5c0-.55.45-1 1-1z"/><path d="M8.75 1.75v3h3"/>',
  chevron: '<path d="M6 4l4 4-4 4"/>',
  search: '<circle cx="7" cy="7" r="4.25"/><path d="M10.25 10.25 13.5 13.5"/>',
  copy: '<rect x="5.25" y="5.25" width="8" height="8" rx="1"/><path d="M10.75 5.25V3.75c0-.55-.45-1-1-1h-6c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h1.5"/>',
  external: '<path d="M9.5 2.75h3.75V6.5M13.25 2.75 7.5 8.5"/><path d="M11.5 9.25v3c0 .55-.45 1-1 1h-6.75c-.55 0-1-.45-1-1V5.5c0-.55.45-1 1-1h3"/>',
  refresh: '<path d="M13 8a5 5 0 1 1-1.46-3.54"/><path d="M13.25 2.5v2.75H10.5"/>',
  box: '<path d="M8 1.75 13.5 4.6v6.8L8 14.25 2.5 11.4V4.6z"/><path d="M2.5 4.6 8 7.5l5.5-2.9M8 7.5v6.75"/>',
  check: '<path d="M3.5 8.5l3 3 6-6.5"/>',
  x: '<path d="M4.5 4.5l7 7M11.5 4.5l-7 7"/>',
  stop: '<rect x="4" y="4" width="8" height="8" rx="1"/>',
  log: '<path d="M3 4h10M3 8h10M3 12h6"/>',
  dot: '<circle cx="8" cy="8" r="2.5" fill="currentColor" stroke="none"/>',
  spark: '<path d="M8 1.75 9.4 6.6l4.85 1.4-4.85 1.4L8 14.25 6.6 9.4 1.75 8l4.85-1.4z"/>',
  gear: '<circle cx="8" cy="8" r="2"/><path d="M8 1.75v1.5M8 12.75v1.5M14.25 8h-1.5M3.25 8h-1.5M12.4 3.6l-1.06 1.06M4.66 11.34 3.6 12.4M12.4 12.4l-1.06-1.06M4.66 4.66 3.6 3.6"/>',
  sliders: '<path d="M2.75 4.5h6.5M12.25 4.5h1M2.75 11.5h1M6.75 11.5h6.5"/><circle cx="10.75" cy="4.5" r="1.5"/><circle cx="5.25" cy="11.5" r="1.5"/>',
  palette: '<path d="M8 2.25a5.75 5.75 0 1 0 0 11.5c.9 0 1.3-.6 1.3-1.2 0-.7-.5-1-.5-1.6 0-.6.5-1.05 1.1-1.05h1.35c1.45 0 2.5-1.1 2.5-2.65 0-2.7-2.6-4-5.75-4z"/><circle cx="5.25" cy="7.25" r=".75" fill="currentColor" stroke="none"/><circle cx="7.75" cy="5" r=".75" fill="currentColor" stroke="none"/><circle cx="10.5" cy="6" r=".75" fill="currentColor" stroke="none"/>',
  target: '<circle cx="8" cy="8" r="5.75"/><circle cx="8" cy="8" r="3"/><circle cx="8" cy="8" r=".75" fill="currentColor" stroke="none"/>',
  info: '<circle cx="8" cy="8" r="5.75"/><path d="M8 7.25v4M8 4.9v.1"/>',
  globe: '<circle cx="8" cy="8" r="5.75"/><path d="M2.25 8h11.5M8 2.25c1.6 1.7 2.4 3.6 2.4 5.75S9.6 12.05 8 13.75C6.4 12.05 5.6 10.15 5.6 8S6.4 3.95 8 2.25z"/>',
  user: '<circle cx="8" cy="5.5" r="2.75"/><path d="M2.75 13.5c.6-2.4 2.7-4 5.25-4s4.65 1.6 5.25 4"/>',
  send: '<path d="M2.5 8 13.5 2.75 10.5 13.25 8 9.5z"/><path d="M8 9.5 13.5 2.75"/>',
};

function icon(name, cls = '') {
  return `<svg class="ic ${cls}" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] || ''}</svg>`;
}

document.querySelectorAll('[data-icon]').forEach((el) => el.insertAdjacentHTML('afterbegin', icon(el.dataset.icon)));
