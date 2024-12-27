var projectBudget = {
    series: [{
        name: 'Total Budget',
        data: [44, 55, 57, 56, 61, 58, 63, 60, 66]
    }, {
        name: 'Amount',
        data: [76, 85, 101, 98, 87, 105, 91, 114, 94]
    }],
    chart: {
        type: 'bar',
        height: 280
    },
    plotOptions: {
        bar: {
            horizontal: false,
            columnWidth: '55%',
        },
    },
    colors: ['#9977f9', '#ff5454'],
    dataLabels: {
        enabled: false
    },
    stroke: {
        show: true,
        width: 2,
        colors: ['transparent']
    },
    xaxis: {
        categories: ['Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct'],
    },
    fill: {
        opacity: 1
    },
    legend: {
        position: 'top'
    },
	responsive: [
	  {
		breakpoint: 480,
		options: {
			chart: {
				height: 250,
                toolbar: {
                    tools: {
                        download: false,
                        zoom: false,
                        zoomin: false,
                        zoomout: false,
                        pan: false,
                        reset: false
                    }
                }
			},
            yaxis: [{
                show: false
            }, {
                show: false
            }]
		}
	  },
	  {
		breakpoint: 576,
		options: {
			chart: {
				height: 250,
                toolbar: {
                    tools: {
                        download: false,
                        zoom: false,
                        zoomin: false,
                        zoomout: false,
                        pan: false,
                        reset: false
                    }
                }
			},
            yaxis: [{
                show: false
            }, {
                show: false
            }]
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 300,
                toolbar: {
                    tools: {
                        download: false,
                        zoom: false,
                        zoomin: false,
                        zoomout: false,
                        pan: false,
                        reset: false
                    }
                }
			},
            yaxis: [{
                show: false
            }, {
                show: false
            }]
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 315,
                toolbar: {
                    tools: {
                        download: false,
                        zoom: false,
                        zoomin: false,
                        zoomout: false,
                        pan: false,
                        reset: false
                    }
                }
			},
            yaxis: [{
                show: false
            }, {
                show: false
            }]
		}
	  },
	  {
		breakpoint: 1200,
		options: {
			chart: {
				height: 300,
			},
		}
	  }
	]
};
var chart = new ApexCharts(document.querySelector("#projectBudget"), projectBudget);
chart.render();


var CurrentBudget = {
    series: [{
        name: "Desktops",
        data: [20, 41, 35, 51, 30, 52, 69, 43, 70]
    }],
    chart: {
        height: 200,
        type: 'line',
        toolbar: {
            show: false
        },
        zoom: {
            enabled: false
        }
    },
    dataLabels: {
        enabled: false
    },
    grid: {
        padding: {
         left: 0,
         right: 0
        }
    },
    stroke: {
      curve: 'smooth',
      width: 3
    },
    colors: ['#58cde4'],
    xaxis: {
        categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'],
        axisTicks: {
            show: false
        }
    },
    yaxis: {
        show: false
    }
};
var chart = new ApexCharts(document.querySelector("#CurrentBudget"), CurrentBudget);
chart.render();


var WorkActivity = {
    series: [{
        name: 'Work Progress',
        data: [51, 40, 58, 51, 70, 80, 65, 81, 70, 88, 61, 42, 90, 100]
    }],
    chart: {
        height: 130,
        type: 'area',
        sparkline: {
          enabled: true
        },
    },
    colors: ['#ff5454'],
    dataLabels: {
        enabled: false
    },
    stroke: {
        width: 2,
        curve: 'smooth'
    },
    xaxis: {
        categories: ["Jan 01", "Jan 02", "Jan 03", "Jan 04", "Jan 05", "Jan 06", "Jan 07", "Jan 08", "Jan 09", "Jan 10", "Jan 11", "Jan 12", "Jan 13", "Jan 14"]
    },
    tooltip: {
        x: {
            format: 'dd/MM/yy HH:mm'
        },
    },
};
var chart = new ApexCharts(document.querySelector("#WorkActivity"), WorkActivity);
chart.render();