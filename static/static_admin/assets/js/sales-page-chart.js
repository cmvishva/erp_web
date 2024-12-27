var optionschartEarning = {
    series: [{
        name: 'Profit',
        type: 'column',
        data: [440, 505, 414, 671, 227, 413, 201, 352, 752, 320, 257, 160],
		color: '#2cc391'
    }, {
        name: 'Growth',
        type: 'line',
        data: [23, 42, 35, 27, 43, 22, 17, 31, 22, 22, 12, 16],
		color: '#ff5454'
    }],
    chart: {
        height: 550,
        type: 'line',
    },
    stroke: {
        width: [0, 4]
    },
    dataLabels: {
        enabled: true,
        enabledOnSeries: [1]
    },
    labels: ['01/01/2022', '02/01/2022', '03/01/2022', '04/01/2022', '05/01/2022', '06/01/2022', '07/01/2022', '08/01/2022', '09/01/2022', '10/01/2022', '11/01/2022', '12/01/2022'],
    xaxis: {
        type: 'datetime'
    },
    yaxis: [{
        title: false
    }, {
        opposite: true,
    }],
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
				height: 350
			}
		}
	  }
	]
};
var chart = new ApexCharts(document.querySelector("#chartEarning"), optionschartEarning);
chart.render();


var optionschartExpense = {
    series: [{
        data: [2, 36, 22, 30, 12, 38]
    }],
    chart: {
        type: "area",
        height: 125,
        sparkline: {
            enabled: !0
        }
    },
    colors: ['#2cc391'],
    stroke: {
        curve: "smooth",
        width: 1.5
    },
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
				height: 100,
			},
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 125,
			},
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 90,
			},
		}
	  },
	  {
		breakpoint: 1199,
		options: {
			chart: {
				height: 110,
			},
		}
	  }
	]
},
chart = new ApexCharts(document.querySelector("#chartExpense"), optionschartExpense);
chart.render();


var optionslineOne = {
    series: [{
        data: [2, 36, 22, 30, 12, 38]
    }],
    chart: {
        type: "area",
        height: 55,
        sparkline: {
            enabled: !0
        }
    },
    colors: ['#2cc391'],
    stroke: {
        curve: "smooth",
        width: 1.5
    },
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
		breakpoint: 576,
		options: {
			chart: {
				height: 50,
			},
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 55
			}
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 45
			}
		}
	  },
	  {
		breakpoint: 1199,
		options: {
			chart: {
				height: 50
			}
		}
	  }
	]
},
chart = new ApexCharts(document.querySelector("#lineOne"), optionslineOne);
chart.render();

var optionslineTwo = {
    series: [{
        data: [30, 18, 32, 15, 42, 38]
    }],
    chart: {
        type: "area",
        height: 55,
        sparkline: {
            enabled: !0
        }
    },
    colors: ['#24af6e'],
    stroke: {
        curve: "smooth",
        width: 1.5
    },
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
		breakpoint: 576,
		options: {
			chart: {
				height: 50,
			},
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 55
			}
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 45
			}
		}
	  },
	  {
		breakpoint: 1199,
		options: {
			chart: {
				height: 50
			}
		}
	  }
	]
},
chart = new ApexCharts(document.querySelector("#lineTwo"), optionslineTwo);
chart.render();

var optionslineThree = {
    series: [{
        data: [5, 30, 15, 40, 12, 38]
    }],
    chart: {
        type: "area",
        height: 55,
        sparkline: {
            enabled: !0
        }
    },
    colors: ['#d31212'],
    stroke: {
        curve: "smooth",
        width: 1.5
    },
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
		breakpoint: 576,
		options: {
			chart: {
				height: 50,
			},
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 55
			}
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 45
			}
		}
	  },
	  {
		breakpoint: 1199,
		options: {
			chart: {
				height: 50
			}
		}
	  }
	]
},
chart = new ApexCharts(document.querySelector("#lineThree"), optionslineThree);
chart.render();

var optionslineFour = {
    series: [{
        data: [10, 25, 15, 25, 15, 18]
    }],
    chart: {
        type: "area",
        height: 55,
        sparkline: {
            enabled: !0
        }
    },
    colors: ['#00add0'],
    stroke: {
        curve: "smooth",
        width: 1.5
    },
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
		breakpoint: 576,
		options: {
			chart: {
				height: 50,
			},
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 55
			}
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 45
			}
		}
	  },
	  {
		breakpoint: 1199,
		options: {
			chart: {
				height: 50
			}
		}
	  }
	]
},
chart = new ApexCharts(document.querySelector("#lineFour"), optionslineFour);
chart.render();



var optionsgroupOne = {
    series: [{
        name: 'Last Week',
        data: [44, 55, 57, 56, 61, 58, 63, 60, 66, 45]
    }, {
        name: 'This Week',
        data: [76, 85, 101, 98, 87, 105, 91, 114, 94, 80]
    }],
    chart: {
        type: 'bar',
        height: 120,
        sparkline: {
            enabled: !0
        }
    },
    colors: ['#58cde4', '#8156F8'],
    plotOptions: {
        bar: {
            horizontal: false,
            columnWidth: '45%',
            endingShape: 'rounded'
        },
    },
    dataLabels: {
        enabled: false
    },
    stroke: {
        show: false,
    },
    xaxis: {
        categories: ['Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov'],
    },
    yaxis: {
    },
    fill: {
        opacity: 1
    },
    tooltip: {
        x: {
            show: false
        },
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
				height: 100,
			},
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 120,
			},
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 80,
			},
		}
	  }
	]
};
var chart = new ApexCharts(document.querySelector("#groupOne"), optionsgroupOne);
chart.render();

var optionsgroupTwo = {
    series: [{
        name: 'Last Week',
        data: [76, 85, 101, 98, 87, 105, 91, 114, 94, 80]
    }, {
        name: 'This Week',
        data: [44, 55, 57, 56, 61, 58, 63, 60, 66, 45]
    }],
    chart: {
        type: 'bar',
        height: 120,
        sparkline: {
            enabled: !0
        }
    },
    colors: ['#42d993', '#ff5454'],
    plotOptions: {
        bar: {
            horizontal: false,
            columnWidth: '45%',
            endingShape: 'rounded'
        },
    },
    dataLabels: {
        enabled: false
    },
    stroke: {
        show: false,
    },
    xaxis: {
        categories: ['Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov'],
    },
    yaxis: {
    },
    fill: {
        opacity: 1
    },
    tooltip: {
        x: {
            show: false
        },
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
				height: 100,
			},
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 120,
			},
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 80,
			},
		}
	  }
	]
};
var chart = new ApexCharts(document.querySelector("#groupTwo"), optionsgroupTwo);
chart.render();

var optionsgroupThree = {
    series: [{
        name: 'Last Week',
        data: [44, 55, 57, 56, 61, 58, 63, 60, 66, 45]
    }, {
        name: 'This Week',
        data: [76, 85, 101, 98, 87, 105, 91, 114, 94, 80]
    }],
    chart: {
        type: 'bar',
        height: 120,
        sparkline: {
            enabled: !0
        }
    },
    colors: ['#9977f9', '#ffd045'],
    plotOptions: {
        bar: {
            horizontal: false,
            columnWidth: '45%',
            endingShape: 'rounded'
        },
    },
    dataLabels: {
        enabled: false
    },
    stroke: {
        show: false,
    },
    xaxis: {
        categories: ['Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov'],
    },
    yaxis: {
    },
    fill: {
        opacity: 1
    },
    tooltip: {
        x: {
            show: false
        },
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
				height: 100,
			},
		}
	  },
	  {
		breakpoint: 768,
		options: {
			chart: {
				height: 120,
			},
		}
	  },
	  {
		breakpoint: 992,
		options: {
			chart: {
				height: 80,
			},
		}
	  }
	]
};
var chart = new ApexCharts(document.querySelector("#groupThree"), optionsgroupThree);
chart.render();