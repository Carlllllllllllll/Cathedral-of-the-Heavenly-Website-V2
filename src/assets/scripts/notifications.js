function showNotification(type, title, message, duration = 5000) {
  const container =
    document.getElementById("notificationContainer") ||
    createNotificationContainer();

  while (container.children.length >= 4) {
    const lastChild = container.lastChild;
    lastChild.style.animation = "slideOutLeft 0.3s ease forwards";
    setTimeout(() => lastChild.remove(), 300);
  }

  const notification = document.createElement("div");
  notification.className = `notification ${type}`;
  notification.setAttribute("role", "alert");

  const icons = {
    success: '<i class="fas fa-check-circle"></i>',
    error: '<i class="fas fa-times-circle"></i>',
    warning: '<i class="fas fa-exclamation-triangle"></i>',
    info: '<i class="fas fa-info-circle"></i>',
  };

  notification.innerHTML = `
        <div class="notification-icon">${icons[type] || icons.info}</div>
        <div class="notification-content">
            <div class="notification-title">${title}</div>
            <div class="notification-message">${message}</div>
        </div>
        <button class="notification-close" type="button" aria-label="إغلاق الإشعار">✕</button>
    `;

  notification
    .querySelector(".notification-close")
    .addEventListener("click", () => {
      notification.style.animation = "slideOutLeft 0.3s ease forwards";
      setTimeout(() => notification.remove(), 300);
    });

  container.prepend(notification);

  setTimeout(() => {
    if (notification.parentElement) {
      notification.style.animation = "slideOutLeft 0.3s ease forwards";
      setTimeout(() => {
        if (notification.parentElement) {
          notification.remove();
        }
      }, 300);
    }
  }, duration);
}

function createNotificationContainer() {
  const container = document.createElement("div");
  container.id = "notificationContainer";
  container.className = "notification-container";
  container.setAttribute("role", "status");
  container.setAttribute("aria-live", "polite");
  container.setAttribute("aria-atomic", "true");
  document.body.appendChild(container);
  return container;
}

window.showNotification = showNotification;

if (typeof module !== "undefined" && module.exports) {
  module.exports = { showNotification };
}
