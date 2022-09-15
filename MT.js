Java.perform(function(){
	
/* 	//先HOOK libc.so->dlopen
	//第三方库导入后，HOOK第三方库中偏移地址为0x000BFA0C的函数。
    var funcname = 'dlopen';
    var funcAddress = Module.findExportByName("libc.so", funcname)   

    var result_pointer;
    var pmValue = '';
    Interceptor.attach(funcAddress,{
        onEnter: function(args){
			this.pmValue = Memory.readUtf8String(args[0]);
			console.log(this.pmValue);
			//if(this.pmValue.indexOf("libgame.so") != -1){
			//	this.found = true;
			//}
        },
        onLeave: function(retval){
			if(this.found){
				console.log('dlopen return value: ' + retval);
				frida_Module();
				dlopentodo();
			}
        }
    }); */
		
		
	var dayin = false;
	var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
	if(android_dlopen_ext != null){
		Interceptor.attach(android_dlopen_ext,{
			onEnter: function(args){
				var soName = args[0].readCString();
				console.log("android_dlopen_ext: " + soName);
				if(soName.indexOf("libgame.so") != -1){//libcocos2dlua.so
					this.hook = true;
				}
			},
			onLeave: function(retval){
				if(this.hook) {
					//frida_Module();
					dlopentodo();
					console.log("hook ok");
				};
			}
		});
	}
	
		
	
function frida_Module() {
    Java.perform(function () {

        var process_Obj_Module_Arr = Process.enumerateModules();
        for(var i = 0; i < process_Obj_Module_Arr.length; i++) {
            //if(process_Obj_Module_Arr[i].path.indexOf("hello")!=-1)
            //{
                console.log("模块名称:",process_Obj_Module_Arr[i].name);
                console.log("模块地址:",process_Obj_Module_Arr[i].base);
                console.log("大小:",process_Obj_Module_Arr[i].size);
                console.log("文件系统路径",process_Obj_Module_Arr[i].path);
            //}
         }
    });
}
//frida_Module();
dlopentodo();


	function dlopentodo(){
		console.log("hook start");
		//加载lua文件函数 libcocos2dlua.so
		var base = Module.findBaseAddress('libgame.so');
		//if(base==null){ base = 0x04000000; }
		var addr = Module.findExportByName(base, "luaL_loadbuffer");
		console.log("luaL_loadbuffer: " + addr);
		if(addr!=null){
			Interceptor.attach(addr,{
				onEnter:function (args){
	/* 			    this.fileout = "/data/local/tmp/frida/lua/" + Memory.readCString(args[3]).split("/").join(".");
					console.log("read file from: " + this.fileout);
					var tmp = Memory.readByteArray(args[1], args[2].toInt32());
					var file = new File(this.fileout, "w");
					file.write(tmp);
					file.flush();
					file.close();

					console.log("lual_loadbuffer (" +Memory.readCString (args[3] ) +" ，" +Memory.readCString (args[1])+")"); */
				},
				onLeave:function (retval){
					//console.log(retval)
				}
			});
		}
		
/* 		//再贴个获取xxtea秘钥的 libcocos2dlua.so _Z13xxtea_decryptPhjS_jPj
		Interceptor.attach(Module.findExportByName("libgame.so" , "xxtea_decode"),{
			onEnter:function (args){
				console.log(Memory.readUtf8String(args[2]));
				console.log("\n");
			},
			onLeave:function (retval){
				//console.log(retval)
			}
		}); */

	}

});


