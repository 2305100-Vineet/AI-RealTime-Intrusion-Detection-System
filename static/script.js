const socket = new WebSocket(
(location.protocol==="https:"?"wss://":"ws://")+location.host+"/ws"
);

const map = L.map('map').setView([20,0],2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

let heatLayer = L.heatLayer([], {
radius: 30,
blur: 25,
maxZoom: 5
}).addTo(map);

let trafficChart = null;
let shapChart = null;

socket.onopen = function(){
setInterval(() => socket.send("update"), 15000);
};

socket.onmessage = function(event){
const data = JSON.parse(event.data);
updateUI(data);
};

function updateUI(data){

// Basic metrics
document.getElementById("traffic").innerText = data.traffic + " packets";
document.getElementById("risk").innerText = data.risk + "%";
document.getElementById("bar").style.width = data.risk + "%";
document.getElementById("threat").innerText = data.threat_level;

// Alarm for high threat
if(data.threat_level === "HIGH" || data.threat_level === "CRITICAL"){
document.getElementById("alarm").play();
}

// Events table
const tbody = document.getElementById("events");
tbody.innerHTML = "";

data.events.forEach(e => {
tbody.innerHTML += `
<tr>
<td>${e.time}</td>
<td>${e.status}</td>
<td>${e.risk}</td>
<td>${e.severity}</td>
</tr>`;
});

// Heatmap
const heatPoints = data.geo.map(g => [g.lat, g.lon, g.intensity]);
heatLayer.setLatLngs(heatPoints);

// Traffic Chart
if(trafficChart) trafficChart.destroy();

trafficChart = new Chart(document.getElementById("trafficChart"), {
type: 'line',
data: {
labels: data.traffic_history.map((_,i)=>i+1),
datasets: [{
label: "Traffic",
data: data.traffic_history,
borderColor: "#00f2ff",
borderWidth: 2,
fill: false
}]
},
options: {
responsive: true,
plugins: { legend: { display: false } }
}
});

// SHAP Chart
if(data.shap_data && data.shap_data.length > 0){

if(shapChart) shapChart.destroy();

shapChart = new Chart(document.getElementById("shapChart"), {
type: 'bar',
data: {
labels: ["F1","F2","F3","F4","F5"],
datasets: [{
label: "Feature Impact",
data: data.shap_data,
backgroundColor: "#00f2ff"
}]
},
options: {
responsive: true
}
});
}

}

// Theme Toggle
function toggleTheme(){
document.body.classList.toggle("light");
}

// Dataset Upload
async function uploadDataset(){
const file = document.getElementById("dataset").files[0];
if(!file){
alert("Select dataset first.");
return;
}
const form = new FormData();
form.append("file", file);
await fetch('/api/upload', { method:'POST', body:form });
alert("Dataset analyzed.");
}

// PDF Download
function downloadReport(){
window.open('/api/report');
}
