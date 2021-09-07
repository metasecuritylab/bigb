### 
Author: suwonchon(schon@ebay.com)
###

class Dashing.PieChart extends Dashing.Widget
  ready: ->
    #console.log '[INFO:ready] Get Data from piechart'

    if not @get('datasets')
      @set 'status', 'NO DATA'

    left = @get('leftMargin') || 0
    right = @get('rightMargin') || left
    top = @get('topMargin') || 0
    bottom = @get('bottomMargin') || top

    container = $(@node).parent()
    width = (Dashing.widget_base_dimensions[0] * container.data("sizex")) + Dashing.widget_margins[0] * 2 * (container.data("sizex") - 1) - left - right
    height = (Dashing.widget_base_dimensions[1] * container.data("sizey")) - 35 - top - bottom

    if !!@get('moreinfo')
      height -= 20

    $holder = $("<div class='canvas-holder' style='left:#{left}px; top:#{top}px; position:absolute;'></div>")
    $(@node).append $holder

    canvas = $(@node).find('.canvas-holder')
    canvas.append("<canvas width=\"#{width}\" height=\"#{height}\" class=\"chart-area\"/>")

    @ctx = $(@node).find('.chart-area')[0].getContext('2d')

    @myChart = new Chart(@ctx, {
      type: 'pie'
      data: {
        labels: @get('labels')
        datasets: @get('datasets')
      }
      options: $.extend({
        responsive: true
        maintainAspectRatio: true
        legend: {
          display: true
        }
      }, @get('options'))
    });

  onData: (data) ->
    #console.log '[INFO:onData] Get Data from piechart'

    status = switch
      when not (data.hasOwnProperty('datasets')) then 'NO DATA'
      when @get('datasets').length < 1 then 'NO DATA'
      else 'success'

    @set 'status', status

    if @myChart
      if data.labels then @myChart.data.labels = data.labels
      if data.datasets then @myChart.data.datasets = data.datasets
      if data.options then @myChart.options = $.extend(data.options, @myChart.options)

      @myChart.update()

