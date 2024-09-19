<!-- Server Selection Handling -->
function selectServer(selectedServer) {
  document.getElementById('serverSelectionDropdown').textContent = selectedServer
  localStorage.setItem('selectedServer', selectedServer)

  var params = new URLSearchParams(window.location.search)
  if(params.has("server")) {
    params.set('server', selectedServer)
    window.location.search = params.toString();
  }
}

function handleLogout() {
  localStorage.removeItem('selectedServer')
}

function viewLocations() {
  const savedServer = 'selectedServer' in localStorage ? localStorage.getItem('selectedServer') : ''
  window.location.href = '/locations?server=' + savedServer
}

document.addEventListener('DOMContentLoaded', function () {
    const savedServer = localStorage.getItem('selectedServer')
    if (savedServer) {
        document.getElementById('serverSelectionDropdown').textContent = savedServer
    }
});

<!-- -->
