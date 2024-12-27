var RevenueVsExpense = {
    series: [{
        name: 'Expenses',
        type: 'area',
        data: [55, 69, 40, 70, 40, 55, 70, 41, 31, 47]
    }, {
        name: 'Revenue',
        type: 'line',
        data: [60, 79, 50, 80, 55, 70, 95, 52, 44, 61]
    }],
    chart: {
        height: 400,
        type: 'line',
    },
    colors: ['#8156F8', '#ffd045'],
    stroke: {
        curve: 'smooth',
        width: 2.5
    },
    fill: {
        type:'solid',
        opacity: [0.35, 1],
    },
    labels: ['Dec 01', 'Dec 02','Dec 03','Dec 04','Dec 05','Dec 06','Dec 07','Dec 08','Dec 09 ','Dec 10'],
    markers: {
        size: 0
    },
    tooltip: {
        shared: true,
        intersect: false,
        y: {
            formatter: function (y) {
                if(typeof y !== "undefined") {
                    return "$ " + y.toFixed(0) + "k";
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
var chart = new ApexCharts(document.querySelector("#RevenueVsExpense"), RevenueVsExpense);
chart.render();


var ActivityChart = {
    series: [
        {
            name: "Income",
            data: [2829, 1930, 2334, 1637, 3233, 2532, 2833]
        },
        {
            name: "Outcome",
            data: [2056, 1156, 1454, 1848, 2764, 1597, 1918]
        }
    ],
    chart: {
        height: 400,
        type: 'line',
        dropShadow: {
            enabled: true,
            color: '#000',
            top: 18,
            left: 7,
            blur: 10,
            opacity: 0.2
        },
    },
    colors: ['#42d993', '#ff5454'],
    stroke: {
        curve: 'smooth',
        width: 2.5
    },
    grid: {
        borderColor: '#e7e7e7',
        row: {
            colors: ['rgba(129, 86, 248, 0.05)', 'transparent'],
            opacity: 0.5
        },
    },
    markers: {
        size: 5,
        hover: {
            size: 7
        }
    },
    xaxis: {
        categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
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
				height: 300,
			},
		}
	  }
	]
};
var chart = new ApexCharts(document.querySelector("#ActivityChart"), ActivityChart);
chart.render();


var staticOne = {
    series: [{
            data: [2829, 1930, 2334, 1637, 3233, 2532, 2833]
        }],
    chart: {
        height: 80,
        type: 'line',
        sparkline: {
            enabled: true
        },
        dropShadow: {
            enabled: true,
            color: '#24af6e',
            top: 5,
            left: 0,
            blur: 5,
            opacity: 0.2
        },
    },
    colors: ['#42d993'],
    stroke: {
        curve: 'smooth',
        width: 2.5
    },
    markers: {
        size: 5,
        hover: {
            size: 7
        }
    },
    xaxis: {
        categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
    },
    tooltip: {
        x: {
            show: false
        }
    }
};
var chart = new ApexCharts(document.querySelector("#staticOne"), staticOne);
chart.render();

var staticTwo = {
    series: [{
            data: [2056, 1156, 1254, 2748, 1864, 1597, 1918]
        }],
    chart: {
        height: 80,
        type: 'line',
        sparkline: {
            enabled: true
        },
        dropShadow: {
            enabled: true,
            color: '#d31212',
            top: 5,
            left: 0,
            blur: 5,
            opacity: 0.2
        },
    },
    colors: ['#ff5454'],
    stroke: {
        curve: 'smooth',
        width: 2.5
    },
    markers: {
        size: 5,
        hover: {
            size: 7
        }
    },
    xaxis: {
        categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
    },
    tooltip: {
        x: {
            show: false
        }
    }
};
var chart = new ApexCharts(document.querySelector("#staticTwo"), staticTwo);
chart.render();

var staticThree = {
    series: [{
            data: [2829, 1930, 2334, 1637, 3233, 2532, 2833]
        }],
    chart: {
        height: 80,
        type: 'line',
        sparkline: {
            enabled: true
        },
        dropShadow: {
            enabled: true,
            color: '#e6ac00',
            top: 5,
            left: 0,
            blur: 5,
            opacity: 0.2
        },
    },
    colors: ['#ffd045'],
    stroke: {
        curve: 'smooth',
        width: 2.5
    },
    markers: {
        size: 5,
        hover: {
            size: 7
        }
    },
    xaxis: {
        categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
    },
    tooltip: {
        x: {
            show: false
        }
    }
};
var chart = new ApexCharts(document.querySelector("#staticThree"), staticThree);
chart.render();

var staticFour = {
    series: [{
            data: [2056, 1156, 1254, 2748, 1864, 1597, 1918]
        }],
    chart: {
        height: 80,
        type: 'line',
        sparkline: {
            enabled: true
        },
        dropShadow: {
            enabled: true,
            color: '#00add0',
            top: 5,
            left: 0,
            blur: 5,
            opacity: 0.2
        },
    },
    colors: ['#58cde4'],
    stroke: {
        curve: 'smooth',
        width: 2.5
    },
    markers: {
        size: 5,
        hover: {
            size: 7
        }
    },
    xaxis: {
        categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
    },
    tooltip: {
        x: {
            show: false
        }
    }
};
var chart = new ApexCharts(document.querySelector("#staticFour"), staticFour);
chart.render();


var SalesByCategory = {
    series: [44, 55, 33, 55],
    chart: {
        type: 'pie',
    },
    legend: {
        position: 'bottom'
    },
    labels: ['WP Themes', 'HTML Themes', 'UI Themes', 'Script'],
    colors: ['#9977f9', '#42d993', '#6935f7', '#ffd045'],
    responsive: [{
        breakpoint: 480,
        options: {
            legend: {
                show: false
            }
        }
    }]
};
var chart = new ApexCharts(document.querySelector("#SalesByCategory"), SalesByCategory);
chart.render();


var IncomeBudget = {
    series: [70],
    chart: {
        height: 300,
        type: 'radialBar',
        dropShadow: {
            enabled: true,
            color: '#6935f7',
            top: 5,
            left: 0,
            blur: 5,
            opacity: 0.2
        },
    },
    colors: ['#8156F8'],
    plotOptions: {
        heatmap: {
            radius: 30,
        },
        radialBar: {
            startAngle: 0,
            endAngle: 360,
            hollow: {
                size: '75%',
            },
            dataLabels: {
                show: true,
                name: {
                    show: true,
                    fontSize: '16px',
                    fontFamily: undefined,
                    fontWeight: 500,
                    color: '#a1a1a1',
                    offsetY: -6
                },
                value: {
                    show: true,
                    fontSize: '20px',
                    fontFamily: undefined,
                    fontWeight: 600,
                    color: '#9977f9',
                    offsetY: 6,
                    formatter: function (val) {
                      return val + '%'
                    }
                },
            },
        },
    },
    labels: ['Income Budget'],
    stroke: {
        lineCap: 'round'
    },
    responsive: [{
        breakpoint: 576,
        options: {
            chart: {
                height: 300
            }
        }
    },{
        breakpoint: 1400,
        options: {
            chart: {
                height: 270
            }
        }
    }]
};
var chart = new ApexCharts(document.querySelector("#IncomeBudget"), IncomeBudget);
chart.render();

var ExpenseBudget = {
    series: [60],
    chart: {
        height: 300,
        type: 'radialBar',
        dropShadow: {
            enabled: true,
            color: '#00add0',
            top: 5,
            left: 0,
            blur: 5,
            opacity: 0.2
        },
    },
    colors: ['#58cde4'],
    plotOptions: {
        heatmap: {
            radius: 30,
        },
        radialBar: {
            startAngle: 0,
            endAngle: 360,
            hollow: {
                size: '75%',
            },
            dataLabels: {
                show: true,
                name: {
                    show: true,
                    fontSize: '16px',
                    fontFamily: undefined,
                    fontWeight: 500,
                    color: '#a1a1a1',
                    offsetY: -6
                },
                value: {
                    show: true,
                    fontSize: '20px',
                    fontFamily: undefined,
                    fontWeight: 600,
                    color: '#58cde4',
                    offsetY: 6,
                    formatter: function (val) {
                      return val + '%'
                    }
                },
            },
        }
    },
    labels: ['Expense Budget'],
    stroke: {
        lineCap: 'round'
    },
    responsive: [{
        breakpoint: 1400,
        options: {
            chart: {
                height: 270
            }
        }
    },{
        breakpoint: 576,
        options: {
            chart: {
                height: 300
            }
        }
    }]
};
var chart = new ApexCharts(document.querySelector("#ExpenseBudget"), ExpenseBudget);
chart.render();