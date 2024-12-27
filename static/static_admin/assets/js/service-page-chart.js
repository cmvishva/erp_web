var optionsRevenue = {
	series: [{
		name: 'Revenue',
		type: 'column',
		data: [23, 11, 22, 27, 13, 22, 37, 21, 44, 22, 30, 50],
		color: '#2cc391'
	}, {
		name: 'Support Cost',
		type: 'area',
		data: [44, 55, 41, 67, 22, 43, 21, 41, 56, 27, 43, 68],
		color: '#fc633b'
	}, {
		name: 'Invest',
		type: 'line',
		data: [30, 25, 36, 30, 45, 35, 64, 52, 59, 36, 39, 62],
		color: '#8156F8'
	}],
		chart: {
		height: 380,
		type: 'line',
		stacked: false,
	},
	stroke: {
		width: [0, 2, 3],
		curve: 'smooth'
	},
	plotOptions: {
		bar: {
		columnWidth: '50%'
		}
	},
	
	fill: {
		opacity: [0.85, 0.25, 1],
		gradient: {
		inverseColors: false,
		shade: 'light',
		type: "vertical",
		opacityFrom: 0.85,
		opacityTo: 0.55,
		stops: [0, 30, 70, 100]
		}
	},
	labels: ['01/01/2022', '02/01/2022', '03/01/2022', '04/01/2022', '05/01/2022', '06/01/2022', '07/01/2022',
		'08/01/2022', '09/01/2022', '10/01/2022', '11/01/2022', '12/01/2022'
	],
	markers: {
		size: 0,
	},
	xaxis: {
		type: 'datetime'
	},
	yaxis: {
		title: false,
		min: 0
	},
	tooltip: {
		shared: true,
		intersect: false,
		y: {
			formatter: function (y) {
				if (typeof y !== "undefined") {
				return y.toFixed(0) + " Dollar";
				}
				return y;
		
			}
		}
	},
	responsive: [
	  {
		breakpoint: 480,
		options: {
			chart: {
				height: 200,
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
				height: 350,
			},
		}
	  }
	]
};
var chartRevenue = new ApexCharts(document.querySelector("#chart-revenue"), optionsRevenue).render();

var optionschartFeedback = {
	series: [35, 30, 20, 15],
	chart: {
		type: 'pie',
	},
	legend: false,
	labels: ['Very Good', 'Good', 'Normal', 'Not Good'],
};
var chart = new ApexCharts(document.querySelector("#chartFeedback"), optionschartFeedback);
chart.render();