
$(document).ready(function () {
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');

    //receive details from server
    socket.on('data', function (msg) {

        console.log("Received number" + msg.total_packets);
        $('#total_packets').html(msg.total_packets.toString());
        $('#total_streams').html(msg.total_streams.toString());
        $('#total_flagged').html(msg.total_flagged.toString());
    });

});


$(document).ready(function () {
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');

    //receive details from server
    socket.on('data', function (msg) {

        console.log("Received number" + msg.total_packets);
        $('#total_packets').html(msg.total_packets.toString());
        $('#total_streams').html(msg.total_streams.toString());
        $('#total_flagged').html(msg.total_flagged.toString());
    });

});