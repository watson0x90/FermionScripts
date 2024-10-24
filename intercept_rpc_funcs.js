function func_pRpcBindingFromStringBinding(){

    let pRpcBindingFromStringBinding = Module.findExportByName("Rpcrt4.dll", "RpcBindingFromStringBindingW");

    Interceptor.attach(pRpcBindingFromStringBinding, {
        onEnter: function(args) {
            send("[>] Called RpcBindingFromStringBindingW");
            send("    |_ StringBinding:       " + args[0].readUtf16String());
            this.bindingHandle = args[1];
        },
        onLeave: function(retval) {
            send("[<] RpcBindingFromStringBindingW returned: " + retval);
            send("    |_ BindingHandle:       " + this.bindingHandle.readPointer());
        }
    }); 

}


function func_RpcBindingSetAuthInfoW(){
    let pRpcBindingSetAuthInfo = Module.findExportByName("Rpcrt4.dll", "RpcBindingSetAuthInfoW");

    Interceptor.attach(pRpcBindingSetAuthInfo, {
        onEnter: function(args) {
            send("[>] Called RpcBindingSetAuthInfoW");
            send("    |_ BindingHandle:       " + args[0]);
            send("    |_ ServerPrincipalName: " + args[1].readUtf16String());
            send("    |_ AuthnLevel:          " + args[2]);
            send("    |_ AuthnSvc:            " + args[3]);
            send("    |_ AuthIdentity:        " + args[4]);
            send("    |_ AuthzSvc:            " + args[5]);
        },
        onLeave: function(retval) {
            send("[<] RpcBindingSetAuthInfoW returned: " + retval);
        }
    });

}

function func_pRpcStringBindingCompose(){
    let pRpcStringBindingCompose = Module.findExportByName("Rpcrt4.dll", "RpcStringBindingComposeW");

    Interceptor.attach(pRpcStringBindingCompose, {
        onEnter: function(args) {
            send("[>] Called RpcStringBindingComposeW");
            send("    |_ ObjUuid:             " + args[0].readUtf16String());
            send("    |_ ProtSeq:             " + args[1].readUtf16String());
            send("    |_ NetworkAddr:         " + args[2].readUtf16String());
            send("    |_ Endpoint:            " + args[3].readUtf16String());
            send("    |_ Options:             " + args[4].readUtf16String());
        },
        onLeave: function(retval) {
            send("[<] RpcStringBindingComposeW returned: " + retval);
        }
    });
}


function func_pRpcServerListen(){
    let pRpcServerListen = Module.findExportByName("Rpcrt4.dll", "RpcServerListen");

    Interceptor.attach(pRpcServerListen, {
        onEnter: function(args) {
            send("[>] Called RpcServerListen");
            send("    |_ MinimumCallThreads:  " + args[0].toInt32());
            send("    |_ MaxCalls:            " + args[1].toInt32());
            send("    |_ DontWait:            " + args[2].toInt32());
        },
        onLeave: function(retval) {
            send("[<] RpcServerListen returned: " + retval);
        }
    });
}

function func_pRpcServerRegisterIf(){
    let pRpcServerRegisterIf = Module.findExportByName("Rpcrt4.dll", "RpcServerRegisterIf");

    Interceptor.attach(pRpcServerRegisterIf, {
        onEnter: function(args) {
            send("[>] Called RpcServerRegisterIf");
            send("    |_ IfSpec:              " + args[0]);
            send("    |_ MgrTypeUuid:         " + args[1]);
            send("    |_ MgrEpv:              " + args[2]);
        },
        onLeave: function(retval) {
            send("[<] RpcServerRegisterIf returned: " + retval);
        }
    });
}

function func_pRpcAsyncCompleteCall(){
    let pRpcAsyncCompleteCall = Module.findExportByName("Rpcrt4.dll", "RpcAsyncCompleteCall");

    Interceptor.attach(pRpcAsyncCompleteCall, {
        onEnter: function(args) {
            send("[>] Called RpcAsyncCompleteCall");
            send("    |_ pAsync:              " + args[0]);
            send("    |_ Reply:               " + args[1]);
        },
        onLeave: function(retval) {
            send("[<] RpcAsyncCompleteCall returned: " + retval);
        }
    });
}

function func_pRpcImpersonateClient(){
    let pRpcImpersonateClient = Module.findExportByName("Rpcrt4.dll", "RpcImpersonateClient");

    Interceptor.attach(pRpcImpersonateClient, {
        onEnter: function(args) {
            send("[>] Called RpcImpersonateClient");
            send("    |_ BindingHandle:       " + args[0]);
        },
        onLeave: function(retval) {
            send("[<] RpcImpersonateClient returned: " + retval);
        }
    });
}

function func_pNdrClientCall2(){
    let pNdrClientCall2 = Module.findExportByName("Rpcrt4.dll", "NdrClientCall2");

    Interceptor.attach(pNdrClientCall2, {
        onEnter: function(args) {
            send("[>] Called NdrClientCall2");
            send("    |_ pMIDL_STUB_DESC:     " + args[0]);
            send("    |_ pFormatString:       " + args[1]);
            send("    |_ StackArguments:      " + args[2]);
        },
        onLeave: function(retval) {
            send("[<] NdrClientCall2 returned: " + retval);
        }
    });
}

func_pNdrClientCall2();
