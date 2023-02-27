
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
			
			ZHttpMessageExtract : script to extract string from  http message by spefic refex While Fuzzing


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
			regexToMatch:String(parameters.get("regex")),
			requestOrResponseOrAll:String(parseOptionsOrDefault(parameters.get("request-response-all"), ["req","res","request","response","all","full"], "all")),
			bodyOrHeadOrAll:String(parseOptionsOrDefault(parameters.get("body-head-all"), ["body","head","header","headers","all","full"],"all")),
			ignoreCase:String(parseOptionsOrDefault(parameters.get("ignore-case (i)"), ["true","false","yes","no","y"], "true")),
	        dotall:String(parseOptionsOrDefault(parameters.get("dotall (s)"), ["true","false","yes","no","y"], "false")),
			unicode:String(parseOptionsOrDefault(parameters.get("unicode (u)"), ["true","false","yes","no","y"], "false")),
			multiline:String(parseOptionsOrDefault(parameters.get("multiline (m)"), ["true","false","yes","no","y"], "false")),
			sticky:String(parseOptionsOrDefault(parameters.get("sticky (y)"), ["true","false","yes","no","y"], "false"))
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

function httpMessageExtract(utils,fuzzResult){
	  

	  const parameters = parseParameters(utils.getParameters())
	  
	  const searchPoll= getSearchPoll(fuzzResult.getHttpMessage(), parameters.requestOrResponseOrAll, parameters.bodyOrHeadOrAll)
	  try{

			const flags=[]
			
			const regex= new RegExp(parameters.regexToMatch)

			if (["true","yes","y"].includes(parameters.ignoreCase) ){
				  flags.push("i")	  
			}
			
			if (["true","yes","y"].includes(parameters.sticky) ){
				  flags.push("y")	  
			}

			if (["true","yes","y"].includes(parameters.multiline) ){
				  flags.push("m")	  
			}
			
			if (["true","yes","y"].includes(parameters.unicode) ){
				  flags.push("u")	  
			}

			if (["true","yes","y"].includes(parameters.dotall) ){
				  flags.push("s")	
			}
			
			const result=searchPoll.match(regex,...flags)

			if( result ){
				  return result[0]
			}
			else{
				  return ""
			}
	  }
	  catch(err){
			return err		
	  }	
	  	  

}

function showHttpMessageExtractResult(utils,fuzzResult){
	  const result = httpMessageExtract(utils, fuzzResult);
	  fuzzResult.addCustomState("Key Custom State", result);
}



function processMessage(utils, message) {
  message.getRequestHeader().setHeader("X-Unique-Id", String(count));
	count++;
}

function processResult(utils, fuzzResult){
	showHttpMessageExtractResult(utils,fuzzResult)
	return true;
}

function getRequiredParamsNames(){
	return ["regex"];
}

function getOptionalParamsNames(){
	return ["request-response-all","body-head-all","ignore-case (i)","dotall (s)","unicode (u)","multiline (m)","sticky (y)"];
}

