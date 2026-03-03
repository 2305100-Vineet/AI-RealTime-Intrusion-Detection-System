const map = L.map('map').setView([20,0],2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
maxZoom:18
}).addTo(map);

async function update(){
const res = await fetch('/api/data');
const data = await res.json();

document.getElementById("traffic").innerText =
data.traffic + " packets";

document.getElementById("risk").innerText =
data.risk + "%";

document.getElementById("bar").style.width =
data.risk + "%";

document.getElementById("threat").innerText =
data.threat_level;

const tbody = document.getElementById("events");
tbody.innerHTML = "";

data.events.forEach(e=>{
tbody.innerHTML +=
`<tr>
<td>${e.time}</td>
<td>${e.status}</td>
<td>${e.risk}</td>
<td>${e.severity}</td>
</tr>`;
});

data.geo.forEach(g=>{
L.circleMarker([g.lat,g.lon],{
radius:5,
color:'red'
}).addTo(map);
});
}

update();
setInterval(update,15000);
