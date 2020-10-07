var canvas = document.getElementById('myAreaChart');
var data = {
  labels: ["0", "1", "2", "3", "4", "5", "6", "7","8", "9"],
  datasets: [
    {
      label: "Packets per second",
      fill: false,
      lineTension: 0.0,
      backgroundColor: "rgba(75,192,192,0.4)",
      borderColor: "rgba(75,192,192,1)",
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
      data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }
  ]
};

var prev = 0;
var zero = 9;
var highest = null;
var lowest = null;
function adddata() {
  highest = null;
  lowest = null;
  var value = document.getElementById("total_packets").innerText;
  var temp = value;

  temp = (Number(value) - prev);
  myLineChart.data.labels.push(zero);
  myLineChart.data.labels.splice(0, 1);
  myLineChart.data.datasets[0].data.splice(0, 1);
  myLineChart.data.datasets[0].data.push(temp);

  var data_list = myLineChart.data.datasets[0].data;

  for (var i = 0; i < myLineChart.data.datasets[0].data.length; i++) {
    if (lowest > data_list[i] || lowest == null) {
      lowest = data_list[i];
      // continue;
    }

    if (highest < data_list[i] || highest == null) {
      highest = data_list[i];
      // continue;
    }
  }
  console.log("highest: " + highest + " | lowest: " + lowest);
  myLineChart.options.scales.yAxes[0].ticks.min = lowest;
  myLineChart.options.scales.yAxes[0].ticks.max = highest;
  myLineChart.update();
  zero++;
  prev = Number(value);
  
}



setInterval(function () { adddata(); }, 2000);



var option = {
  layout:{
    padding:{
      bottom:55
    }
  },
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
  borderHeight: 1000
});