
$(document).ready(function (){
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');

    //receive details from server
    socket.on('data', function (msg) {
        $('#total_packets').html(msg.total_packets.toString());
        $('#total_streams').html(msg.total_streams.toString());
        $('#total_flagged').html(msg.total_flagged.toString());
    });


    $("#save").click(function(){
        var btn = document.getElementById("save");
        var save = btn.innerHTML;
        console.log(save);
        if (btn.innerHTML == "Save"){
            console.log("change to stop saving");
            btn.innerHTML = "Stop Saving";
        }else{
            console.log("change to Save");
            btn.innerHTML = "Save";
        }
        var a = {'data':save};
        $.ajax({
            type:'post',
            url:'/save',
            contentType: "application/json",
            data:JSON.stringify(a),
            success:function(data){
            }
        });  
            
    });

    $("#viewflagged").click(function(){
        var btn = document.getElementById("save");
        var save = btn.innerHTML;
        console.log(save);
        if (btn.innerHTML == "Save"){
            console.log("change to stop saving");
            btn.innerHTML = "Stop Saving";
        }else{
            console.log("change to Save");
            btn.innerHTML = "Save";
        }
        var a = {'data':save};
        $.ajax({
            type:'post',
            url:'/save',
            contentType: "application/json",
            data:JSON.stringify(a),
            success:function(data){
            }
        });  
            
    });

});

