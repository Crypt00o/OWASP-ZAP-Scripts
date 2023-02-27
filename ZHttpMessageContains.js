
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
			requestOrResponseOrAll:String(parseOptionsOrDefault(parameters.get("request-response-all"), ["req","res","request","response","all","full"], "all")),
			bodyOrHeadOrAll:String(parseOptionsOrDefault(parameters.get("body-head-all"), ["body","head","header","headers","all","full"],"all")),
			ignoreCase:String(parseOptionsOrDefault(parameters.get("ignore-case"), ["true","false","yes","no"], "true"))
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

	  if(["req","request","all","full"].includes(requestOrResponseOrAll) ){
		
			if(["body","all","full"].includes( bodyOrHeadOrAll)  ){
				  toSearchIn= `${toSearchIn}
				  ${httpMessage.req.body}`
			}
			
			if(["head","header","headers","all","full"].includes( bodyOrHeadOrAll)  ){
				   toSearchIn= `${toSearchIn}
				  ${httpMessage.req.head}`

			}
			  
	  }
	  
	  if(["res","response","all","full"].includes(requestOrResponseOrAll) ){
		
			if(["body","all","full"].includes( bodyOrHeadOrAll) ){
				  toSearchIn= `${toSearchIn}
				  ${httpMessage.res.body}`
			}
			
			if(["head","header","headers","all","full"].includes( bodyOrHeadOrAll)  ){
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

