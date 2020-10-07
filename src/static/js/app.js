
$(document).ready(function (){
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');

    //receive details from server
    socket.on('data', function (msg) {
        $('#total_packets').html(msg.total_packets.toString());
        $('#total_streams').html(msg.total_streams.toString());
        $('#total_flagged').html(msg.total_flagged.toString());
    });

});


$(document).ready(function(){

    $("#save").click(function(){
        change();
        $.ajax({
            type:'post',
            url:'/save',
            success:function(data){
                change();
            }
    
        });  
        
    });

});


function change(){
    var btn = document.getElementById("save");

    if (btn.innerHTML.equals("Save"))
        btn.innerHTML = "Stop Saving";
    else
        btn.innerHTML = "Save";

}