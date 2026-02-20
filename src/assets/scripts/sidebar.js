const whenReady = (callback) => {
  if (typeof callback !== "function") return
  let fired = false
  const run = () => {
    if (fired) return
    fired = true
    callback()
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run, { once: true })
    window.addEventListener("load", run, { once: true })
    window.addEventListener("pageshow", run, { once: true })
  } else {
    ;(typeof queueMicrotask === "function"
      ? queueMicrotask
      : (fn) => Promise.resolve().then(fn))(run)
  }
}

whenReady(() => {
  const sidebar = document.getElementById("sidebar")
  const hamburgerMenu = document.querySelector(".hamburger-menu")

  if (!sidebar || !hamburgerMenu) return

  hamburgerMenu.addEventListener("click", (event) => {
    event.stopPropagation()
    sidebar.classList.toggle("show")
    hamburgerMenu.classList.toggle("active")
  })

  document.addEventListener("click", (event) => {
    if (!sidebar.contains(event.target) && !hamburgerMenu.contains(event.target)) {
      sidebar.classList.remove("show")
      hamburgerMenu.classList.remove("active")
    }
  })

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      sidebar.classList.remove("show")
      hamburgerMenu.classList.remove("active")
    }
  })
})
