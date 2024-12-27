var optionscurrentDeal = {
    series: [{
        data: [82, 96, 70, 82, 52, 78]
    }],
    chart: {
        type: "area",
        height: 320,
    },
    colors: ['#2cc391'],
    stroke: {
        curve: "smooth",
        width: 1.5
    },
    labels: ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN'],
    tooltip: {
        fixed: {
            enabled: !1
        },
        x: {
            show: !1
        },
        y: {
            title: {
                formatter: function(e) {
                    return ""
                }
            }
        },
        marker: {
            show: !1
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
	  }
	]
},
chart = new ApexCharts(document.querySelector("#currentDeal"), optionscurrentDeal);
chart.render();


var optionschartTransiction = {
    series: [{
        name: 'FACEBOOK',
        data: [44, 55, 57, 56, 61, 58, 63, 60, 66, 75, 50, 60 ]
    }, {
        name: 'YOUTUBE',
        data: [76, 85, 101, 98, 87, 105, 91, 114, 94, 90, 65, 75]
    }, {
        name: 'GOOGLE',
        data: [35, 41, 36, 26, 45, 48, 52, 53, 41, 65, 40, 50]
    }],
    chart: {
        type: 'bar',
        height: 450
    },
    colors: ['#2cc391', '#58cde4', '#24af6e'],
    plotOptions: {
        bar: {
            horizontal: false,
            columnWidth: '55%',
        },
    },
    dataLabels: {
        enabled: false
    },
    stroke: {
        show: true,
        width: 2,
        colors: ['transparent']
    },
    xaxis: {
        grid: {
            show: false
        },
        categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
    },
    fill: {
        opacity: 1
    },
    tooltip: {
        y: {
            formatter: function (val) {
                return "$ " + val + " thousands"
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
	  }
	]
};
var chart = new ApexCharts(document.querySelector("#chartTransiction"), optionschartTransiction);
chart.render();


var optionsSaleStatic = {
    series: [{
        name: 'Sale',
        data: [58, 63, 60, 66, 75, 50, 60 ]
    }, {
        name: 'Profit',
        data: [105, 91, 114, 94, 90, 65, 75]
    }],
    chart: {
        type: 'bar',
        height: 300
    },
    colors: ['#ffd045', '#42d993'],
    plotOptions: {
        bar: {
            horizontal: false,
            columnWidth: '55%',
        },
    },
    dataLabels: {
        enabled: false
    },
    stroke: {
        show: true,
        width: 2,
        colors: ['transparent']
    },
    xaxis: {
        grid: {
            show: false
        },
        categories: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'],
    },
    yaxis: {
      title: {
        text: 'Last Week'
      }
    },
    fill: {
        opacity: 1
    },
    tooltip: {
        y: {
            formatter: function (val) {
                return val
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
	  }
	]
};
var chart = new ApexCharts(document.querySelector("#SaleStatic"), optionsSaleStatic);
chart.render();


var CustomerSatisfaction = {
    series: [40, 30, 20, 10],
    labels: ['very good', 'good', 'avarage', 'bad'],
    colors: ['#42d993', '#8156F8', '#ffd045', '#ff5454'],
    chart: {
        type: 'donut',
        height: 345
    },
    legend: {
        position: 'bottom'
    },
};
var chart = new ApexCharts(document.querySelector("#CustomerSatisfaction"), CustomerSatisfaction);
chart.render();