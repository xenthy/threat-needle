var canvas = document.getElementById('myAreaChart');
var data = {
  labels: ["00:00", "00:00", "00:00", "00:00", "00:00", "00:00", "00:00", "00:00", "00:00", "00:00"],
  datasets: [
    {
      
      label: "Packets/Second",
      fill: false,
      lineTension: 0.0,
      backgroundColor: "rgba(75,192,192,0.4)",
      borderColor: "#4e73df",
      borderCapStyle: 'butt',
      borderDash: [],
      borderDashOffset: 0.0,
      borderJoinStyle: 'miter',
      pointBorderColor: "rgba(75,192,192,1)",
      pointBackgroundColor: "#fff",
      pointBorderWidth: 1,
      pointHoverRadius: 5,
      pointHoverBackgroundColor: "rgba(75,192,192,1)",
      pointHoverBorderColor: "rgba(220,220,220,1)",
      pointHoverBorderWidth: 2,
      pointRadius: 5,
      pointHitRadius: 10,
      data: [0, 0, 0, 0, 0 ,0, 0, 0, 0,0]
    },
    {
      
        label: "Streams/Second",
        fill: false,
        lineTension: 0.0,
        backgroundColor: "rgba(75,192,192,0.4)",
        borderColor: "#20c9a6",
        borderCapStyle: 'butt',
        borderDash: [],
        borderDashOffset: 0.0,
        borderJoinStyle: 'miter',
        pointBorderColor: "rgba(75,192,192,1)",
        pointBackgroundColor: "#fff",
        pointBorderWidth: 1,
        pointHoverRadius: 5,
        pointHoverBackgroundColor: "rgba(75,192,192,1)",
        pointHoverBorderColor: "rgba(220,220,220,1)",
        pointHoverBorderWidth: 2,
        pointRadius: 5,
        pointHitRadius: 10,
        data: [0, 0, 0, 0, 0 ,0, 0, 0, 0,0]
    },

    {
      
      label: "Flagged Packets/Second",
      fill: false,
      lineTension: 0.0,
      backgroundColor: "rgba(75,192,192,0.4)",
      borderColor: "#e74a3b",
      borderCapStyle: 'butt',
      borderDash: [],
      borderDashOffset: 0.0,
      borderJoinStyle: 'miter',
      pointBorderColor: "rgba(75,192,192,1)",
      pointBackgroundColor: "#fff",
      pointBorderWidth: 1,
      pointHoverRadius: 5,
      pointHoverBackgroundColor: "rgba(75,192,192,1)",
      pointHoverBorderColor: "rgba(220,220,220,1)",
      pointHoverBorderWidth: 2,
      pointRadius: 5,
      pointHitRadius: 10,
      data: [0, 0, 0, 0, 0 ,0, 0, 0, 0,0]
  }
  ]
};


var prev = 0;
var prev_stream = 0;
var prev_flagged=0;

var time = "00:00";
var a=0;

var highest = null;
var lowest = null;

function add_data() {
    highest = null;
    lowest = null;
    var pkts = document.getElementById("total_packets").innerText;
    var stream_count = document.getElementById("total_streams").innerText;
    var flagged_count =document.getElementById("total_flagged").innerText;
    var str = myLineChart.data.labels.slice(-1)[0];
    if(str.slice(-2) == "59"){
        a = Number(str.slice(0,2)) + 1;
        if(a < 10){
            time = "0" + a + ":00";
        }else{
            time =  a + ":00";
        }
        
    }else{
        a = Number(str.slice(-2)) + 1;
        if( a < 10){
            time = str.slice(0,3) + "0" + a;
        }else{
            time = str.slice(0,3) + "" + a;
        }
    }

    myLineChart.data.labels.push(time);
    myLineChart.data.labels.splice(0, 1);

    var temp = pkts;
    temp = (Number(pkts) - prev);
    myLineChart.data.datasets[0].data.splice(0, 1);
    myLineChart.data.datasets[0].data.push(temp);


    temp = (Number(stream_count) - prev_stream);
    myLineChart.data.datasets[1].data.splice(0, 1);
    myLineChart.data.datasets[1].data.push(temp);

    temp = (Number(flagged_count) - prev_flagged);
    myLineChart.data.datasets[2].data.splice(0, 1);
    myLineChart.data.datasets[2].data.push(temp);
    
    var data_list = myLineChart.data.datasets[0].data;

    for (var i = 0; i < myLineChart.data.datasets[0].data.length; i++) {
        if (highest < data_list[i] || highest == null) {
        highest = data_list[i];
        }
    }
   // myLineChart.options.scales.yAxes[0].ticks.min = lowest;
    myLineChart.options.scales.yAxes[0].ticks.max = highest;
    myLineChart.update();
    prev = Number(pkts);
    prev_stream = Number(stream_count);
    prev_flagged = Number(flagged_count);
  
}



setInterval(function () { add_data(); }, 2000);
var option = {
  showLines: true,
  scales: {
    yAxes: [{
      display: true,
      ticks: {
        beginAtZero: true,
        min: 0,
        max: 1000
      }
    }]
   
  }
};

var myLineChart = Chart.Line(canvas, {
  data: data,
  options: option,
});