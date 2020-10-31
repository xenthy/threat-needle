// Set new default font family and font color to mimic Bootstrap's default styling
Chart.defaults.global.defaultFontFamily = 'Nunito', '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
Chart.defaults.global.defaultFontColor = '#858796';

// Pie Chart Example
var ctx = document.getElementById("myPieChart");
var myPieChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ["Protocol"],
        datasets: [{
            data: [1],
            backgroundColor: ['#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b', '#858796', '#f8f9fc', '#5a5c69'],
        }],
    },
    options: {
        maintainAspectRatio: false,
        tooltips: {
            backgroundColor: "rgb(255,255,255)",
            bodyFontColor: "#858796",
            borderColor: '#dddfeb',
            borderWidth: 1,
            xPadding: 15,
            yPadding: 15,
            displayColors: false,
            caretPadding: 10,
        },
        legend: {
            display: true
        },
        cutoutPercentage: 80,
    },
});


function add_pie_data() {
    var a = { 'data': "getpiedata" };
    $.ajax({
        type: 'post',
        url: '/',
        contentType: "application/json",
        data: JSON.stringify(a),
        success: function (data) {
            myPieChart.data.labels = [];
            myPieChart.data.datasets[0].data = [];
            Object.keys(data).forEach(function (key) {
                myPieChart.data.labels.push(key);
                myPieChart.data.datasets[0].data.push(data[key])
            })
            myPieChart.update();
        }
    });

}


setInterval(function () { add_pie_data(); }, 5000);