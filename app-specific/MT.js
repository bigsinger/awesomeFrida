Java.perform(function () {

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

	// 常量定义
	var PACKAGENAME = "com.zyzc.mt";
	var SAVEDIR = "cache"



	var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
	if (android_dlopen_ext != null) {
		Interceptor.attach(android_dlopen_ext, {
			onEnter: function (args) {
				var soName = args[0].readCString();
				if (soName.indexOf("libgame.so") != -1) {//libcocos2dlua.so
					console.log("android_dlopen_ext: " + soName);
					this.hook = true;
				}
			},
			onLeave: function (retval) {
				if (this.hook) {
					//frida_Module();
					dlopentodo();
					console.log("hook ok");
				};
			}
		});
	}

	// 字节序列保存到文件中
	function save2File(filename, bytes) {
		console.log("save file to: " + filename);
		var file = new File(filename, "w");
		file.write(bytes);
		file.flush();
		file.close();
	}

	// 输出显示十六进制数据
	function printDataHexStr(byteArr, size) {
		var len = size;
		if (len == undefined) { len = 0x40; }
		console.log(byteArr);

		/* 	var b = new Uint8Array(byteArr);
			var str = "";
		
			for(var i = 0; i < len; i++) {
				str += (b[i].toString(16) + " ");
			}
			console.log(str); */
	}

	function frida_Module() {
		Java.perform(function () {

			var modules = Process.enumerateModules();
			for (var i = 0; i < modules.length; i++) {
				if (modules[i].path.indexOf("libgame") != -1) {
					console.log("模块名称:", modules[i].name);
					console.log("模块地址:", modules[i].base);
					console.log("大小:", modules[i].size);
					console.log("文件系统路径", modules[i].path);
				}
			}
		});
	}


	function dlopentodo() {
		console.log("hook start");

		//getFileData
		Interceptor.attach(Module.findExportByName("libgame.so", "_ZN7cocos2d11CCFileUtils11getFileDataEPKcS2_Pmb"), {
			onEnter: function (args) {
				var name = Memory.readCString(args[1]);
				this.fileDescriptor = name;
				this.sizePtr = ptr(args[3]);
				if (name.indexOf("ea_autofight_list.lua") != -1) {
					console.log("getFileData onEnter, name: " + name);
				}
			},
			onLeave: function (retval) {
				if (this.fileDescriptor.indexOf("ea_autofight_list.lua") != -1) {
					var name = this.fileDescriptor;
					var size = Memory.readInt(this.sizePtr);
					console.log("getFileData onLeave, name: " + name + " size: ", size);
					//var buff = Memory.readCString(retval);
					//console.log(buff);
					printDataHexStr(Memory.readByteArray(retval, size));

					if (!name.endsWith(".lua")) { name = name + ".lua"; }
					var filename = "/data/user/0/" + PACKAGENAME + "/" + SAVEDIR + "/" + name.split("/").join(".");
					save2File(filename, Memory.readByteArray(retval, size));
				}
			}
		});

		//luaL_loadbuffer 加载lua文件函数 libcocos2dlua.so
		var addr = Module.findExportByName('libgame.so', "luaL_loadbuffer");
		console.log("luaL_loadbuffer: " + addr);
		if (addr != null) {
			Interceptor.attach(addr, {
				onEnter: function (args) {
					var name = Memory.readCString(args[3]);
					if (name == "ea_autofight_list") {
						var buff = Memory.readCString(args[1]);
						var size = args[2].toInt32();
						//console.log("lual_loadbuffer, name: " + name + " size: ", size);
						//console.log(buff);
						var byteArr = Memory.readByteArray(args[1], size);
						printDataHexStr(byteArr);

						if (!name.endsWith(".lua")) { name = name + ".lua"; }
						var filename = "/data/user/0/" + PACKAGENAME + "/" + SAVEDIR + "/" + name.split("/").join(".");
						save2File(filename, byteArr);
					}
				}
			});
		}

		/* 		
				Interceptor.attach(Module.findExportByName("libgame.so" , "_ZN7cocos2d11CCLuaEngine13executeStringEPKc"),{
					onEnter:function (args){
						console.log(' called from:\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
					},
					onLeave:function (retval){
						//console.log(retval)
					}
				});
				
					Interceptor.attach(Module.findExportByName("libc.so" , "open"),{
					onEnter:function (args){
						var name = Memory.readUtf8String(args[0]);
						if(name.indexOf(".lua")!=-1){
							console.log(
							  "open(" +
							  "path=\"" + name + "\"" +
							  ", flag=" + args[1] +
								")"
							);
							console.log('called from:\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');	
						}
					}
				});
				
				Interceptor.attach(Module.findExportByName("libgame.so" , "_ZN13CScriptSystem6DoFileEPKc"),{
					onEnter:function (args){
						var name = Memory.readCString(args[1]);
						console.log("DoFile: " + name);
						//console.log('called from:\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
					}
				});
		*/


		//再贴个获取xxtea秘钥的 libcocos2dlua.so _Z13xxtea_decryptPhjS_jPj

		Interceptor.attach(Module.findExportByName("libgame.so", "_Z13getPackagekeyiPi"), {
			onEnter: function (args) {
				console.log("getPackagekey onEnter");
			},
			onLeave: function (retval) {
				console.log("getPackagekey onLeave");
			}
		});
		Interceptor.attach(Module.findExportByName("libgame.so", "npk_read_encrypt"), {
			onEnter: function (args) {
				console.log("npk_read_encrypt onEnter");
			},
			onLeave: function (retval) {
				console.log("npk_read_encrypt onLeave");
			}
		});

		Interceptor.attach(Module.findExportByName("libgame.so", "tea_decode_buffer"), {
			onEnter: function (args) {
				console.log("tea_decode_buffer");
				var pKey = ptr(arg[2]);
				console.log("tea_decode_buffer key: ", Memory.readUInt(pKey), Memory.readUInt(pKey + 4), Memory.readUInt(pKey + 8), Memory.readUInt(pKey + _12));
			}
		});
		Interceptor.attach(Module.findExportByName("libgame.so", "tea_decode"), {
			onEnter: function (args) {
				console.log("tea_decode");
			}
		});
		Interceptor.attach(Module.findExportByName("libgame.so", "npk_read_encrypt"), {
			onEnter: function (args) {
				console.log("npk_read_encrypt");
				var pKey = ptr(arg[0]);
				console.log("tea_decode_buffer key: ", Memory.readUInt(pKey), Memory.readUInt(pKey + 4), Memory.readUInt(pKey + 8), Memory.readUInt(pKey + _12));
			}
		});

		/* 		Interceptor.attach(Module.findExportByName("libgame.so" , "xxtea_decode"),{
					onEnter:function (args){
						console.log("xxtea: xxtea_decode");// +Memory.readUtf8String(args[2])
					}
				}); */
		Interceptor.attach(Module.findExportByName("libgame.so", "xxtea_decode_byte"), {
			onEnter: function (args) {
				console.log("xxtea: xxtea_decode_byte");
			},
			onLeave: function (retval) {
				//console.log(retval)
			}
		});
		Interceptor.attach(Module.findExportByName("libgame.so", "xxtea_decode_buffer"), {
			onEnter: function (args) {
				console.log("xxtea: xxtea_decode_buffer");
			},
			onLeave: function (retval) {
				//console.log(retval)
			}
		});

		/* 		Interceptor.attach(Module.findExportByName("libgame.so" , "xxtea_encode"),{
					onEnter:function (args){
						console.log("xxtea: xxtea_encode");
					}
				}); */
		Interceptor.attach(Module.findExportByName("libgame.so", "xxtea_encode_byte"), {
			onEnter: function (args) {
				console.log("xxtea: xxtea_encode_byte");
			}
		});
		Interceptor.attach(Module.findExportByName("libgame.so", "xxtea_encode_buffer"), {
			onEnter: function (args) {
				console.log("xxtea: xxtea_encode_buffer");
			}
		});


	}

});


