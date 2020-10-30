var nodes = null;
var edges = null;
var network = null;

function draw(){
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
var a = {'data':"getnetwork"};
$.ajax({
    type: 'post',
    url: '/network',
    contentType: "application/json",
    data: JSON.stringify(a),
    success: function (data) {
        console.log(data)
        nodes = new vis.DataSet();
        data[1].forEach(item => nodes.add({ip:item, value: 1, label: item}));
        console.log(nodes.length)
        
    }
});

var container = document.getElementById("mynetwork");
var data = {
    nodes: nodes
    // edges: edges,
};
var options = {
    nodes: {
        shape: "dot",
    },
};


network = new vis.Network(container, data, options);

}
    // var a = {'data':"getnetwork"};
    // $.ajax({
    //     type: 'post',
    //     url: '/network',
    //     contentType: "application/json",
    //     data: JSON.stringify(a),
    //     success: function (data) {
    //         console.log(data)
    //         nodes = [];
    //         Object.keys(data).forEach(function (key) {
    //             console.log(key)
    //             ip0_exist = false;
    //             ip1_exist = false;
    //             for (var i = 0; i < nodes.length; i++) {
    //                 if (key[0] == nodes[i].ip || !ip0_exist) {
    //                     ip0_exist = true;
    //                 } // for
    //                 if (key[1] == nodes[i].ip || !ip1_exist) {
    //                     ip1_exist = true;
    //                 } // for
    //             } // for

    //             if (!ip0_exist) {
    //                 nodes.push({ id: key[0], value: 1, label: key[0] });
    //             }
    //             if (!ip1_exist) {
    //                 nodes.push({ id: key[1], value: 1, label: key[1] });
    //             }
    //         })
    //     }
    // });


function draw2(){
    


}


setInterval(function () { draw2(); }, 10000);


window.addEventListener("load", () => {
    draw();
});
