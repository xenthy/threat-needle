
$(document).ready(function (){

    $("#save").click(function(e){
        e.preventDefault();
        var btn = document.getElementById("save");
        var status = document.getElementById("status");
        var save = btn.innerHTML;
        console.log(save);
        if (btn.innerHTML == "Save"){
            btn.innerHTML = "Stop Saving";
            status.innerHTML ="Capturing"
        }else{
            console.log("change to Save");
            btn.innerHTML = "Save";
            status.innerHTML = "Monitoring"
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

    $(".payload").click(function(){
        var a = {'data':$(this).val()};
        $.ajax({

            type:'post',
            url:'/flagged',
            contentType: "application/json",
            data:JSON.stringify(a),
            success:function(data){
                document.getElementById("payload").innerHTML = data;
            },
            error: function(XMLHttpRequest, textStatus, errorThrown) { 
                alert("Status: " + textStatus); alert("Error: " + errorThrown); 
            }

        });    

    });


});

