function addLocation(event) {
  event.preventDefault();

  const name = document.getElementById("name").value
  const latitude = document.getElementById("latitude").value
  const longitude = document.getElementById("longitude").value
  json = JSON.stringify({
    tag: name,
    lat: parseFloat(latitude),
    lon: parseFloat(longitude)})
  document.getElementById('jsonData').value = json

  const savedServer = localStorage.getItem('selectedServer')
  document.getElementById('server').value = savedServer

  event.target.submit()
  return false
}

function shareLocation(event) {
  event.preventDefault();

  const savedServer = localStorage.getItem('selectedServer')
  document.getElementById('server').value = savedServer

  event.target.submit()
  return false
}
