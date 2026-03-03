const socket = new WebSocket("ws://"+location.host+"/ws");

socket.onmessage = function(event){
const data = JSON.parse(event.data);
updateUI(data);
addLog(data);
updateMap(data);
};

function updateUI(data){
document.getElementById("status").innerText=data.status;
document.getElementById("riskPercent").innerText=data.risk_score+"%";
}

function addLog(data){
let table=document.getElementById("logTable");
let row=table.insertRow(0);
row.insertCell(0).innerText=new Date().toLocaleTimeString();
row.insertCell(1).innerText=data.status;
row.insertCell(2).innerText=data.risk_score+"%";
row.insertCell(3).innerText=data.severity;
row.insertCell(4).innerText=data.ip;
}

function updateMap(data){
if(data.risk_score>50){
worldMap.data.datasets[0].data.push({
x:Math.random()*360-180,
y:Math.random()*180-90,
r:5
});
worldMap.update();
}
}