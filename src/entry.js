'use strict';
/* Unified JSTV subscription entry. Each embedded module keeps its own scope. */
const http=require('http');
let activeServer=null;
function dispatch(base,req,res){
 const pathname=String(req.url||'/').split('?')[0];
 if(pathname.startsWith('/spider/hongguo_local/3/')){hongguo.handle(req,res);return}
 return base(req,res);
}
async function start(config){
 const factory=globalThis.catServerFactory;
 globalThis.catServerFactory=base=>{
  const handler=(req,res)=>dispatch(base,req,res);
  const server=typeof factory==='function'?factory(handler):http.createServer(handler);
  const listen=server.listen.bind(server);
  server.listen=(options,...args)=>listen(typeof options==='object'?{...options,host:'127.0.0.1'}:options,...args);
  activeServer=server;hongguo.attachServer(server);return server;
 };
 try{await upstream.start(config||{})}finally{globalThis.catServerFactory=factory}
}
async function stop(){
 try{await upstream.stop()}finally{await hongguo.stop();activeServer=null}
}
module.exports={start,stop,getServer:()=>activeServer};
