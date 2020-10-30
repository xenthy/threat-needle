var nodes = null;
var edges = null;
var network = null;

function draw() {
    // create people.
    // value corresponds with the age of the person
    var a = ""; Object.keys(data).forEach(function (key) {
        myPieChart.data.labels.push(key);
        myPieChart.data.datasets[0].data.push(data[key])
    })
    nodes = [];
    $.ajax({
        type: 'post',
        url: '/network',
        contentType: "application/json",
        data: JSON.stringify(a),
        success: function (data) {
            Object.keys(data).forEach(function (key) {
                console.log(key)
                ip0_exist = false;
                ip1_exist = false;
                for (var i = 0; i < nodes.length; i++) {
                    if (key[0] == nodes[i].ip || !ip0_exist) {
                        ip0_exist = true;
                    } // for
                    if (key[1] == nodes[i].ip || !ip1_exist) {
                        ip1_exist = true;
                    } // for
                } // for

                if (!ip0_exist) {
                    nodes.push({ id: key[0], value: 1, label: key[0] });
                }

                if (!ip1_exist) {
                    nodes.push({ id: key[1], value: 1, label: key[1] });
                }
            })
        }
    });

    // nodes = [
    //     { id: 1, value: 1, label: "Algie" },
    //     { id: 2, value: 1, label: "Alston" },
    //     { id: 3, value: 1, label: "Barney" },
    //     { id: 4, value: 1, label: "Coley" },
    //     { id: 5, value: 1, label: "Grant" },
    //     { id: 6, value: 1, label: "Langdon" },
    //     { id: 7, value: 1, label: "Lee" },
    //     { id: 8, value: 1, label: "Merlin" },
    //     { id: 9, value: 1, label: "Mick" },
    //     { id: 10, value: 1, label: "Tod" },
    // ];

    // create connections between people
    // value corresponds with the amount of contact between two people
    // edges = [
    //     { from: 2, to: 8, value: 3, title: "3 emails per week" },
    //     { from: 2, to: 9, value: 5, title: "5 emails per week" },
    //     { from: 2, to: 10, value: 1, title: "1 emails per week" },
    //     { from: 4, to: 6, value: 8, title: "8 emails per week" },
    //     { from: 5, to: 7, value: 2, title: "2 emails per week" },
    //     { from: 4, to: 5, value: 1, title: "1 emails per week" },
    //     { from: 9, to: 10, value: 2, title: "2 emails per week" },
    //     { from: 2, to: 3, value: 6, title: "6 emails per week" },
    //     { from: 3, to: 9, value: 4, title: "4 emails per week" },
    //     { from: 5, to: 3, value: 1, title: "1 emails per week" },
    //     { from: 2, to: 7, value: 4, title: "4 emails per week" },
    // ];
    edges = []
    // Instantiate our network object.
    var container = document.getElementById("mynetwork");
    var data = {
        nodes: nodes,
        edges: edges,
    };
    var options = {
        nodes: {
            shape: "dot",
        },
    };
    network = new vis.Network(container, data, options);
}



window.addEventListener("load", () => {
    draw();
});
