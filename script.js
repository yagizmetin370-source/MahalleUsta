
let player;
let season = 1;

function log(t){
  const el=document.getElementById("log");
  el.innerHTML += t + "<br>";
  el.scrollTop = el.scrollHeight;
}

function startGame(){
  player={
    name:"Player",
    age:18,
    overall:60,
    potential:90,
    goals:0,
    assists:0,
    money:1000,
    stamina:100,
    morale:70
  };
  season=1;
  switchScreen("game");
  updateUI();
  log("Kariyer başladı.");
}

function updateUI(){
  document.getElementById("playerInfo").innerText =
    `Sezon ${season} | OVR ${player.overall} | Gol ${player.goals} | Asist ${player.assists}`;
  document.getElementById("money").innerText = "$"+player.money;
}

function train(){
  let gain=Math.random()*2;
  player.overall=Math.min(player.potential,player.overall+gain);
  player.stamina-=10;
  player.morale+=1;
  log("Antrenman yaptın. +" + gain.toFixed(1) + " OVR");
  updateUI();
}

function playMatch(){
  let perf = Math.random()*100;
  if(perf>60){player.goals++; log("Gol attın!");}
  if(perf>40){player.assists++; log("Asist yaptın!");}
  if(perf>70){player.overall+=0.5;}
  player.money += Math.floor(200+Math.random()*300);
  player.stamina-=20;
  player.morale+=2;
  log("Maç tamamlandı.");
  updateUI();
}

function nextSeason(){
  season++;
  player.age++;
  player.stamina=100;
  player.morale=70;
  player.money+=1000;
  if(player.age>34){log("Emekli oldun. Kariyer bitti.");}
  else log("Yeni sezon başladı.");
  updateUI();
}

function saveGame(){
  localStorage.setItem("career",JSON.stringify({player,season}));
  log("Kaydedildi.");
}

function loadGame(){
  let s=localStorage.getItem("career");
  if(!s){alert("Kayıt yok");return;}
  let d=JSON.parse(s);
  player=d.player; season=d.season;
  switchScreen("game");
  updateUI();
  log("Kayıt yüklendi.");
}

function exitMenu(){
  switchScreen("menu");
}

function switchScreen(id){
  document.querySelectorAll(".screen").forEach(s=>s.classList.remove("active"));
  document.getElementById(id).classList.add("active");
}
