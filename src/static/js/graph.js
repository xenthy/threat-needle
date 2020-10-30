var nodes = null;
var edges = null;
var network = null;

function draw() {
    // nodes = new vis.DataSet([
    //     { id: 1, value: 1, label: "Algie" },
    //     { id: 2, value: 1, label: "Alston" },
    //     { id: 3, value: 1, label: "Barney" }
    // ]);
    // edges = new vis.DataSet([
    //         { from: 2, to: 1, value: 3, title: "3 emails per week" },
    //         { from: 2, to: 4, value: 5, title: "5 emails per week" }
    //     ]);

    // Instantiate our network object.
    // if(!edges || !nodes){
    //     return;
    // }
    var a = { 'data': "getnetwork" };
    $.ajax({
        type: 'post',
        url: '/network',
        contentType: "application/json",
        data: JSON.stringify(a),
        success: function (data) {
            var mapping = data[0];
            var ip_list = data[1];
            var mal_list = data[2];
            console.log(mal_list.length);
            nodes = new vis.DataSet();
            edges = new vis.DataSet();
            ip_list.forEach(function(item){
                if(mal_list.includes(item)){
                    
                    nodes.add({id: item, value: 1, label: item, color: {
                        border: '#2B7CE9',
                        background: '#e74a3b',
                    }});
                }else{
                    nodes.add({id: item, value: 1, label: item, color: {
                        border: '#2B7CE9',
                        background: '#858796',
                    }});
                }
                
            });

            for (const [key, value] of Object.entries(mapping)) {
                k = key.split(',');
                edges.add({from:k[0], to:k[1], value:value ,title: value+" packets"});
            }
     
            var container = document.getElementById("mynetwork");

            var data = {
                nodes: nodes,
                edges: edges
            };

            var w = document.getElementById("graph_card");
            var options = {
                width: "100%",
                height: "100%",
                nodes: {
                    shape: "dot",
                },
            };
            network = new vis.Network(container, data, options);
        }
    });






}
setInterval(function () { draw(); }, 30000);

window.addEventListener("load", () => {
    draw();
});
