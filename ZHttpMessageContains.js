
var count = 1;
/*
 *
 
 *  
 
 ██████╗ ██╗  ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗  ██████╗  ██████╗ 
██╔═████╗╚██╗██╔╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═████╗██╔═████╗██╔═══██╗
██║██╔██║ ╚███╔╝ ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║██╔██║██║██╔██║██║   ██║
████╔╝██║ ██╔██╗ ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ████╔╝██║████╔╝██║██║   ██║
╚██████╔╝██╔╝ ██╗╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝╚██████╔╝╚██████╔╝
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝  ╚═════╝  ╚═════╝ 
                                                                                      
	  https://github.com/Crypt00o/OWASP-ZAP-Scripts
			
			ZHttpMessageContains : script to check if http message contain spefic string While Fuzzing

 * */


function parseOptionsOrDefault(option,options,defaultOption){
	  if (options.includes(String(option).toLowerCase())){
			return option
	  }
	  else{
			return defaultOption
	  }
}


function parseParameters(parameters){
	  	  
	  return {
			textToMatch:String(parameters.get("text")),
			requestOrResponseOrAll:String(parseOptionsOrDefault(parameters.get("request-response-all"), ["req","res","request","response","all"], "all")),
			bodyOrHeadOrAll:String(parseOptionsOrDefault(parameters.get("body-head-all"), ["body","head","header","all"], "all")),
			ignoreCase:String(parseOptionsOrDefault(parameters.get("ignore-case"), ["true","false"], "true"))
	  }

}
	  

function processHttpMessage(message){
	  return {
			 res:{
				  body:String(message.getResponseBody()),
				  head:String(message.getResponseHeader())
			 },
				  req:{
						body:String(message.getRequestBody()),
						head:String(message.getRequestHeader())
			 }
	  }

}



function getSearchPoll(rawHttpMessage,requestOrResponseOrAll,bodyOrHeadOrAll){
	  
	  let toSearchIn=String("")
	  
	  const httpMessage = processHttpMessage(rawHttpMessage)

	  if(requestOrResponseOrAll == "req" || requestOrResponseOrAll=="request" || requestOrResponseOrAll=="all"){
		
			if(bodyOrHeadOrAll=="body" || bodyOrHeadOrAll=="all"  ){
				  toSearchIn= `${toSearchIn}
				  ${httpMessage.req.body}`
			}
			
			if(bodyOrHeadOrAll=="head" || bodyOrHeadOrAll=="header"  || bodyOrHeadOrAll=="all"  ){
				   toSearchIn= `${toSearchIn}
				  ${httpMessage.req.head}`

			}
			  
	  }
	  
	  if(requestOrResponseOrAll == "res" || requestOrResponseOrAll=="response" || requestOrResponseOrAll=="all"){
		
			if(bodyOrHeadOrAll=="body" || bodyOrHeadOrAll=="all"  ){
				  toSearchIn= `${toSearchIn}
				  ${httpMessage.res.body}`
			}
			
			if(bodyOrHeadOrAll=="head" || bodyOrHeadOrAll=="header"  || bodyOrHeadOrAll=="all"  ){
				   toSearchIn= `${toSearchIn}
				  ${httpMessage.res.head}`
			}

	  }

	  return toSearchIn
 
}

function httpMessageContains(utils,fuzzResult){
	  
	  const parameters= parseParameters(utils.getParameters())
	  
	  const searchPoll= getSearchPoll(fuzzResult.getHttpMessage(), parameters.requestOrResponseOrAll, parameters.bodyOrHeadOrAll)
	  
	  if (parameters.ignoreCase=="true" ){
			return  searchPoll.toLowerCase().includes(parameters.textToMatch.toLowerCase())
	  }

	  else{
			return searchPoll.includes(parameters.textToMatch)
	  }

	  

}

function showHttpMessageContainsResult(utils,fuzzResult){
	  const result = httpMessageContains(utils, fuzzResult)? "Text Found" : "Text Not Found" ;
	  fuzzResult.addCustomState("Key Custom State", result);
}



function processMessage(utils, message) {
  message.getRequestHeader().setHeader("X-Unique-Id", String(count));
	count++;
}

function processResult(utils, fuzzResult){
	showHttpMessageContainsResult(utils,fuzzResult)
	return true;
}

function getRequiredParamsNames(){
	return ["text"];
}

function getOptionalParamsNames(){
	return ["request-response-all","body-head-all","ignore-case"];
}

